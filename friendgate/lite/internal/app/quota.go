package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type quotaWindow struct {
	UsedPercent        float64 `json:"used_percent"`
	LimitWindowSeconds int64   `json:"limit_window_seconds"`
	ResetAfterSeconds  int64   `json:"reset_after_seconds"`
	ResetAt            int64   `json:"reset_at"`
}

type quotaRateLimit struct {
	Allowed         bool         `json:"allowed"`
	LimitReached    bool         `json:"limit_reached"`
	PrimaryWindow   *quotaWindow `json:"primary_window"`
	SecondaryWindow *quotaWindow `json:"secondary_window"`
}

type quotaResetCredit struct {
	ExpiresAt      string `json:"expires_at"`
	ExpiresAtCamel string `json:"expiresAt"`
	ResetType      string `json:"reset_type"`
	ResetTypeCamel string `json:"resetType"`
	Status         string `json:"status"`
}

type quotaResetCredits struct {
	AvailableCount int                `json:"available_count"`
	Credits        []quotaResetCredit `json:"credits"`
}

type quotaUsagePayload struct {
	PlanType              string             `json:"plan_type"`
	RateLimit             *quotaRateLimit    `json:"rate_limit"`
	RateLimitResetCredits *quotaResetCredits `json:"rate_limit_reset_credits"`
}

type AccountQuotaSnapshot struct {
	PlanType         string   `json:"plan_type"`
	FiveHourUsed     float64  `json:"quota_5h_used"`
	FiveHourResetAt  int64    `json:"quota_5h_reset_at"`
	SevenDayUsed     float64  `json:"quota_7d_used"`
	SevenDayResetAt  int64    `json:"quota_7d_reset_at"`
	FetchedAt        int64    `json:"fetched_at"`
	ResetCredits     int      `json:"reset_credits"`
	ResetCreditTimes []string `json:"reset_credit_times,omitempty"`
	CooldownUntil    int64    `json:"cooldown_until,omitempty"`
}

type AccountQuotaResetResult struct {
	Code         string `json:"code"`
	WindowsReset int    `json:"windows_reset"`
}

func (s *Server) quotaSyncLoop(ctx context.Context) {
	s.runScheduledQuotaSync(ctx)
	ticker := time.NewTicker(s.cfg.QuotaSyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runScheduledQuotaSync(ctx)
		}
	}
}

func (s *Server) runScheduledQuotaSync(ctx context.Context) {
	if !s.beginRuntimeOperation() {
		return
	}
	defer s.restoreGate.RUnlock()
	s.syncAllAccountQuotas(ctx)
}

func (s *Server) syncAllAccountQuotas(ctx context.Context) {
	accounts, err := s.store.ListAccounts(ctx)
	if err != nil {
		return
	}
	for _, account := range accounts {
		if !account.Active || ctx.Err() != nil {
			continue
		}
		if _, err := s.syncAccountQuota(ctx, account.ID); err != nil {
			s.store.MarkAccountQuotaError(context.Background(), account.ID, err.Error())
		}
	}
}

func (s *Server) syncAccountQuota(ctx context.Context, accountID int64) (*AccountQuotaSnapshot, error) {
	lock := s.accountLifecycleMutex(accountID)
	lock.Lock()
	defer lock.Unlock()
	return s.syncAccountQuotaLocked(ctx, accountID)
}

func (s *Server) syncAccountQuotaLocked(ctx context.Context, accountID int64) (*AccountQuotaSnapshot, error) {
	account, err := s.refreshAccountIfNeededLocked(ctx, &Account{ID: accountID})
	if err != nil {
		return nil, fmt.Errorf("refresh auth: %w", err)
	}
	var usage quotaUsagePayload
	if err := s.doQuotaRequest(ctx, account, http.MethodGet, "/usage", nil, &usage); err != nil {
		return nil, err
	}
	now := time.Now()
	snapshot := AccountQuotaSnapshot{
		PlanType: usage.PlanType, FiveHourUsed: -1, SevenDayUsed: -1, FetchedAt: now.Unix(),
	}
	applyQuotaWindow(&snapshot, usage.RateLimit, now)
	if usage.RateLimit != nil && (usage.RateLimit.LimitReached || !usage.RateLimit.Allowed) && snapshot.CooldownUntil <= now.Unix() {
		snapshot.CooldownUntil = now.Add(s.cfg.AccountCooldown).Unix()
	}
	if usage.RateLimitResetCredits != nil {
		snapshot.ResetCredits = usage.RateLimitResetCredits.AvailableCount
		snapshot.ResetCreditTimes = availableCreditExpirations(usage.RateLimitResetCredits.Credits)
	}
	if count, expirations, ok := s.queryQuotaResetCredits(ctx, account); ok {
		snapshot.ResetCredits = count
		snapshot.ResetCreditTimes = expirations
	}
	if err := s.store.UpdateAccountQuota(ctx, accountID, snapshot); err != nil {
		return nil, err
	}
	return &snapshot, nil
}

func applyQuotaWindow(snapshot *AccountQuotaSnapshot, limit *quotaRateLimit, now time.Time) {
	if limit == nil {
		return
	}
	windows := []*quotaWindow{limit.PrimaryWindow, limit.SecondaryWindow}
	for index, window := range windows {
		if window == nil {
			continue
		}
		resetAt := window.ResetAt
		if resetAt <= 0 && window.ResetAfterSeconds > 0 {
			resetAt = now.Unix() + window.ResetAfterSeconds
		}
		used := window.UsedPercent
		if used < 0 {
			used = 0
		}
		if used > 100 {
			used = 100
		}
		isFiveHour := window.LimitWindowSeconds > 0 && window.LimitWindowSeconds <= 24*60*60
		if window.LimitWindowSeconds == 0 {
			isFiveHour = index == 0
		}
		if isFiveHour {
			snapshot.FiveHourUsed = used
			snapshot.FiveHourResetAt = resetAt
		} else {
			snapshot.SevenDayUsed = used
			snapshot.SevenDayResetAt = resetAt
		}
		if (used >= 100 || limit.LimitReached || !limit.Allowed) && resetAt > snapshot.CooldownUntil {
			snapshot.CooldownUntil = resetAt
		}
	}
}

func (s *Server) queryQuotaResetCredits(ctx context.Context, account *Account) (int, []string, bool) {
	var raw json.RawMessage
	if err := s.doQuotaRequest(ctx, account, http.MethodGet, "/rate-limit-reset-credits", nil, &raw); err != nil {
		return 0, nil, false
	}
	return parseQuotaResetCredits(raw)
}

func parseQuotaResetCredits(raw []byte) (int, []string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return 0, nil, false
	}
	var credits []*quotaResetCredit
	var count *int
	listPresent := false
	if trimmed[0] == '[' {
		if json.Unmarshal(trimmed, &credits) != nil {
			return 0, nil, false
		}
		listPresent = true
	} else {
		var object map[string]json.RawMessage
		if json.Unmarshal(trimmed, &object) != nil {
			return 0, nil, false
		}
		count = flexibleNonNegativeInt(object["available_count"], object["availableCount"])
		for _, key := range []string{"credits", "rate_limit_reset_credits", "items", "data"} {
			value, exists := object[key]
			if !exists || len(bytes.TrimSpace(value)) == 0 || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				continue
			}
			if json.Unmarshal(value, &credits) != nil {
				return valueOrZero(count), nil, count != nil
			}
			listPresent = true
			break
		}
	}
	available := 0
	var expirations []string
	for _, credit := range credits {
		if credit == nil {
			continue
		}
		resetType := strings.TrimSpace(credit.ResetType)
		if resetType == "" {
			resetType = strings.TrimSpace(credit.ResetTypeCamel)
		}
		if resetType != "" && !strings.EqualFold(resetType, "codex_rate_limits") {
			continue
		}
		if status := strings.TrimSpace(credit.Status); status != "" && !strings.EqualFold(status, "available") {
			continue
		}
		available++
		expires := strings.TrimSpace(credit.ExpiresAt)
		if expires == "" {
			expires = strings.TrimSpace(credit.ExpiresAtCamel)
		}
		if expires != "" {
			expirations = append(expirations, expires)
		}
	}
	sortCreditExpirations(expirations)
	if count != nil {
		return *count, expirations, true
	}
	if listPresent {
		return available, expirations, true
	}
	return 0, nil, false
}

func flexibleNonNegativeInt(values ...json.RawMessage) *int {
	for _, raw := range values {
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
			continue
		}
		var value int
		if trimmed[0] == '"' {
			var text string
			if json.Unmarshal(trimmed, &text) != nil {
				continue
			}
			parsed, err := strconv.Atoi(strings.TrimSpace(text))
			if err != nil {
				continue
			}
			value = parsed
		} else if json.Unmarshal(trimmed, &value) != nil {
			continue
		}
		if value >= 0 {
			return &value
		}
	}
	return nil
}

func valueOrZero(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}

func availableCreditExpirations(credits []quotaResetCredit) []string {
	var result []string
	for _, credit := range credits {
		resetType := strings.TrimSpace(credit.ResetType)
		if resetType == "" {
			resetType = strings.TrimSpace(credit.ResetTypeCamel)
		}
		if resetType != "" && !strings.EqualFold(resetType, "codex_rate_limits") {
			continue
		}
		if status := strings.TrimSpace(credit.Status); status != "" && !strings.EqualFold(status, "available") {
			continue
		}
		expires := strings.TrimSpace(credit.ExpiresAt)
		if expires == "" {
			expires = strings.TrimSpace(credit.ExpiresAtCamel)
		}
		if expires != "" {
			result = append(result, expires)
		}
	}
	sortCreditExpirations(result)
	return result
}

func sortCreditExpirations(values []string) {
	sort.SliceStable(values, func(i, j int) bool {
		left, leftErr := time.Parse(time.RFC3339, values[i])
		right, rightErr := time.Parse(time.RFC3339, values[j])
		switch {
		case leftErr == nil && rightErr == nil:
			return left.Before(right)
		case leftErr == nil:
			return true
		case rightErr == nil:
			return false
		default:
			return values[i] < values[j]
		}
	})
}

func (s *Server) resetAccountQuota(ctx context.Context, accountID int64) (*AccountQuotaResetResult, error) {
	lock := s.accountLifecycleMutex(accountID)
	lock.Lock()
	defer lock.Unlock()
	account, err := s.refreshAccountIfNeededLocked(ctx, &Account{ID: accountID})
	if err != nil {
		return nil, err
	}
	redeemID, err := quotaRedeemRequestID()
	if err != nil {
		return nil, err
	}
	var result AccountQuotaResetResult
	if err := s.doQuotaRequest(ctx, account, http.MethodPost, "/rate-limit-reset-credits/consume", map[string]string{"redeem_request_id": redeemID}, &result); err != nil {
		return nil, err
	}
	if _, err := s.syncAccountQuotaLocked(ctx, accountID); err != nil {
		s.store.MarkAccountQuotaError(context.Background(), accountID, err.Error())
	}
	return &result, nil
}

func (s *Server) doQuotaRequest(ctx context.Context, account *Account, method, path string, body any, target any) error {
	callCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(callCtx, method, s.cfg.QuotaBaseURL+path, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+account.AccessToken)
	request.Header.Set("ChatGPT-Account-ID", account.ChatGPTAccountID)
	request.Header.Set("OpenAI-Beta", "codex-1")
	request.Header.Set("OAI-Language", "zh-CN")
	request.Header.Set("Originator", "Codex Desktop")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Sec-Fetch-Site", "none")
	request.Header.Set("Sec-Fetch-Mode", "no-cors")
	request.Header.Set("Sec-Fetch-Dest", "empty")
	request.Header.Set("Priority", "u=4, i")
	request.Header.Set("User-Agent", defaultCodexUA)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := s.client.Do(request)
	if err != nil {
		return fmt.Errorf("quota request: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("quota upstream status %d", response.StatusCode)
	}
	if target == nil || len(bytes.TrimSpace(responseBody)) == 0 {
		return nil
	}
	if raw, ok := target.(*json.RawMessage); ok {
		*raw = append((*raw)[:0], responseBody...)
		return nil
	}
	if err := json.Unmarshal(responseBody, target); err != nil {
		return errors.New("invalid quota response")
	}
	return nil
}

func quotaRedeemRequestID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value)
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:]), nil
}
