package app

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// RequireActiveAccount is called under the same lifecycle mutex used by
// account deletion. It closes the gap between account selection and admitting
// the request to the upstream transport.
func (s *Store) RequireActiveAccount(ctx context.Context, id int64) error {
	var marker int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM accounts WHERE id=? AND active=1 AND access_token_enc<>''`, id).Scan(&marker)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNoAccount
	}
	return err
}

// accountLifecycleMutex serializes every operation which may use or replace an
// account credential. Deletion takes the same lock, so once deletion returns
// there cannot be an older token refresh, model sync, quota query or quota
// reset still using the destroyed credential or writing into its tombstone.
func (s *Server) accountLifecycleMutex(accountID int64) *sync.Mutex {
	lockValue, _ := s.refreshLocks.LoadOrStore(accountID, &sync.Mutex{})
	return lockValue.(*sync.Mutex)
}

// DeleteAccount keeps a credential-free tombstone so historical usage and
// existing Key foreign keys remain readable. All material capable of reaching
// ChatGPT is destroyed in the same transaction and the account disappears
// from administrator listings immediately.
func (s *Store) DeleteAccount(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var marker int
	if err = tx.QueryRowContext(ctx, `SELECT 1 FROM accounts WHERE id=? AND access_token_enc<>''`, id).Scan(&marker); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM session_affinities WHERE account_id=?`, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE invitations SET account_id=NULL WHERE account_id=?`, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM account_models WHERE account_id=?`, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM account_model_snapshots WHERE account_id=?`, id); err != nil {
		return err
	}
	now := time.Now().Unix()
	result, err := tx.ExecContext(ctx, `UPDATE accounts SET
active=0,max_concurrency=0,access_token_enc='',refresh_token_enc='',chatgpt_account_id='',client_id='',expires_at=0,
last_error='',cooldown_until=0,plan_type='',quota_5h_used=-1,quota_5h_reset_at=0,quota_7d_used=-1,
quota_7d_reset_at=0,quota_updated_at=0,quota_error='',reset_credits=0,reset_credit_times='[]',updated_at=?
WHERE id=? AND access_token_enc<>''`, now, id)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrNotFound
	}
	return tx.Commit()
}

func (s *Server) cancelAccountRequestsLocked(accountID int64) []<-chan struct{} {
	var pending []<-chan struct{}
	for keyID, requests := range s.keyRequests {
		for requestID, request := range requests {
			if request.accountID != accountID {
				continue
			}
			request.cancel(errAccountAccessRevoked)
			pending = append(pending, request.done)
			delete(requests, requestID)
		}
		if len(requests) == 0 {
			delete(s.keyRequests, keyID)
		}
	}
	return pending
}

// updateAccountState shares the credential lifecycle lock with refresh,
// quota and model synchronization. Disabling additionally changes the live
// row while key admission is closed, cancels every request already using the
// account and waits for those requests to leave before returning. Therefore a
// successful disable response is a strict boundary: the old OAuth credential
// can no longer be in use after the administrator sees it.
func (s *Server) updateAccountState(ctx context.Context, id int64, active bool) (int, error) {
	lifecycleLock := s.accountLifecycleMutex(id)
	lifecycleLock.Lock()
	defer lifecycleLock.Unlock()

	s.keyRequestMu.Lock()
	if err := s.store.UpdateAccountState(ctx, id, active); err != nil {
		s.keyRequestMu.Unlock()
		return 0, err
	}
	var pending []<-chan struct{}
	if !active {
		pending = s.cancelAccountRequestsLocked(id)
	}
	s.keyRequestMu.Unlock()
	if err := waitKeyRequests(ctx, pending); err != nil {
		return len(pending), err
	}
	return len(pending), nil
}

func (s *Server) deleteAccount(ctx context.Context, id int64) (int, error) {
	// Serialize with token refresh so a refresh response cannot restore the
	// credentials after this operation has returned.
	refreshLock := s.accountLifecycleMutex(id)
	refreshLock.Lock()
	defer refreshLock.Unlock()

	s.keyRequestMu.Lock()
	if err := s.store.DeleteAccount(ctx, id); err != nil {
		s.keyRequestMu.Unlock()
		return 0, err
	}
	pending := s.cancelAccountRequestsLocked(id)
	s.keyRequestMu.Unlock()
	if err := waitKeyRequests(ctx, pending); err != nil {
		return len(pending), err
	}
	return len(pending), nil
}

func (s *Server) adminDeleteAccount(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "账号编号无效")
		return
	}
	cancelled, err := s.deleteAccount(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrRequestDrainTimeout) {
			writeError(w, http.StatusGatewayTimeout, "request_drain_timeout", "账号凭据已删除，但等待旧请求退出超时")
		} else if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "账号不存在或已经删除")
		} else {
			slog.Error("ChatGPT account deletion failed", "account_id", id, "error", err)
			writeError(w, http.StatusInternalServerError, "delete_failed", "删除账号失败")
		}
		return
	}
	s.store.Audit(r.Context(), "admin", "account.deleted", strconv.FormatInt(id, 10), s.realIP(r), map[string]any{
		"effect":             "oauth_credentials/model_snapshot/affinity_destroyed",
		"cancelled_requests": cancelled,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cancelled_requests": cancelled})
}
