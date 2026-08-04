package app

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
)

func (s *Server) adminPlatformStore(w http.ResponseWriter) *PlatformStore {
	store := s.store.Platform()
	if store == nil {
		writeError(w, http.StatusServiceUnavailable, "postgres_not_configured", "统一 PostgreSQL 数据库尚未配置；现有网关数据不会被自动替换")
		return nil
	}
	return store
}

// auditPlatformAdmin keeps the legacy transition audit intact while writing
// the same administrative action to PostgreSQL, which is the authority for
// the new product domain. A transient audit write failure is recorded as a
// runtime security fault rather than rolling back an already committed state
// change and misleading the administrator about its effect.
func (s *Server) auditPlatformAdmin(r *http.Request, action, targetKind, targetID string, metadata any) {
	s.store.Audit(r.Context(), "admin", action, targetID, s.realIP(r), metadata)
	if platform := s.store.Platform(); platform != nil {
		if err := platform.RecordPlatformAudit(r.Context(), "admin", action, targetKind, targetID, s.realIP(r), metadata); err != nil {
			s.setSecurityRuntimeFailure("platform_admin_audit", err)
		}
	}
}

func (s *Server) adminPlatformOverview(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	overview, err := store.Overview(r.Context())
	if err != nil {
		writePlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, overview)
}

func (s *Server) adminPlatformDashboard(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	result, err := store.PlatformDashboard(r.Context())
	if err != nil {
		writePlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) adminListPlatformUsage(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	items, err := store.ListPlatformUsage(r.Context(), platformAdminLimit(r, 100))
	if err != nil {
		writePlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) adminListPlatformWallets(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	items, err := store.ListPlatformWalletSummaries(r.Context(), r.URL.Query().Get("user_id"))
	if err != nil {
		writePlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) adminCreditPlatformWallet(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	var body struct {
		Tokens int64  `json:"tokens"`
		Reason string `json:"reason"`
	}
	if !decodeJSON(w, r, 8<<10, &body) {
		return
	}
	scope := ProductScope(strings.TrimSpace(r.PathValue("scope")))
	if err := store.GrantPlatformWalletTokens(r.Context(), r.PathValue("id"), scope, body.Tokens, body.Reason); err != nil {
		writePlatformError(w, err)
		return
	}
	s.auditPlatformAdmin(r, "wallet.recharged", "wallet", r.PathValue("id")+":"+string(scope), map[string]any{"tokens": body.Tokens, "reason": body.Reason})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) adminListPlatformAudits(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	items, err := store.ListPlatformAudits(r.Context(), platformAdminLimit(r, 100))
	if err != nil {
		writePlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) adminListPaymentProviders(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	items, err := store.ListPaymentProviders(r.Context())
	if err != nil {
		writePlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) adminCreatePaymentProvider(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	var input PaymentProviderInput
	if !decodeJSON(w, r, 1<<20, &input) {
		return
	}
	item, err := store.CreatePaymentProvider(r.Context(), input)
	if err != nil {
		writePlatformError(w, err)
		return
	}
	s.auditPlatformAdmin(r, "payment_provider.created_disabled", "payment_provider", item.ID, map[string]any{"provider_type": item.ProviderType, "merchant_id": item.MerchantID})
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) adminUpdatePaymentProvider(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if !decodeJSON(w, r, 4<<10, &body) {
		return
	}
	if err := store.SetPaymentProviderEnabled(r.Context(), r.PathValue("id"), body.Enabled); err != nil {
		writePlatformError(w, err)
		return
	}
	s.auditPlatformAdmin(r, "payment_provider.disabled", "payment_provider", r.PathValue("id"), nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) adminListPaymentOrders(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	items, err := store.ListPaymentOrders(r.Context(), platformAdminLimit(r, 100))
	if err != nil {
		writePlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func platformAdminLimit(r *http.Request, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))
	if err != nil || value <= 0 {
		return fallback
	}
	if value > 500 {
		return 500
	}
	return value
}

// The browser can run the non-mutating preflight so the administrator sees a
// deterministic report before maintenance.  Applying a snapshot is rejected
// here because it must run while all legacy writers are stopped; the offline
// `migrate --apply` command is the only supported cutover preparation path.
func (s *Server) adminPlatformLegacyImport(w http.ResponseWriter, r *http.Request) {
	if s.adminPlatformStore(w) == nil {
		return
	}
	var body struct {
		Apply bool `json:"apply"`
	}
	if !decodeJSON(w, r, 4<<10, &body) {
		return
	}
	if body.Apply {
		writeError(w, http.StatusConflict, "offline_migration_required", "正式导入必须停止服务后通过 migrate --apply 执行，以保证一致性")
		return
	}
	report, err := s.store.ImportLegacyToPlatform(r.Context(), false)
	if err != nil {
		writePlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) adminListPlatformModels(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	models, err := store.ListPlatformModels(r.Context())
	if err != nil {
		writePlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, models)
}

func (s *Server) adminCreatePlatformModel(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	var input PlatformModelInput
	if !decodeJSON(w, r, 64<<10, &input) {
		return
	}
	model, err := store.CreatePlatformModel(r.Context(), input)
	if err != nil {
		writePlatformError(w, err)
		return
	}
	s.auditPlatformAdmin(r, "platform_model.created", "platform_model", model.ID, map[string]any{"model_key": model.ModelKey})
	writeJSON(w, http.StatusCreated, model)
}

func (s *Server) adminUpdatePlatformModel(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	var input PlatformModelInput
	if !decodeJSON(w, r, 64<<10, &input) {
		return
	}
	model, err := store.UpdatePlatformModel(r.Context(), r.PathValue("id"), input)
	if err != nil {
		writePlatformError(w, err)
		return
	}
	s.auditPlatformAdmin(r, "platform_model.updated", "platform_model", model.ID, map[string]any{"model_key": model.ModelKey})
	writeJSON(w, http.StatusOK, model)
}

func (s *Server) adminListProductModelPublications(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	items, err := store.ListProductModelPublications(r.Context(), r.URL.Query().Get("model_id"))
	if err != nil {
		writePlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) adminUpsertProductModelPublication(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	var input ProductModelPublicationInput
	if !decodeJSON(w, r, 32<<10, &input) {
		return
	}
	item, err := store.UpsertProductModelPublication(r.Context(), input)
	if err != nil {
		writePlatformError(w, err)
		return
	}
	s.auditPlatformAdmin(r, "platform.model_publication.upserted", "model_publication", item.ID, map[string]any{"model_id": item.ModelID, "product_scope": item.ProductScope, "protocol": item.Protocol, "enabled": item.Enabled})
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) adminListPlatformPlans(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	plans, err := store.ListPlans(r.Context())
	if err != nil {
		writePlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, plans)
}

func (s *Server) adminPlatformRegistrationMode(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	mode, err := store.RegistrationMode(r.Context())
	if err != nil {
		writePlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"mode": string(mode)})
}

func (s *Server) adminSetPlatformRegistrationMode(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	var body struct {
		Mode RegistrationMode `json:"mode"`
	}
	if !decodeJSON(w, r, 4<<10, &body) {
		return
	}
	if err := store.SetRegistrationMode(r.Context(), body.Mode, ""); err != nil {
		writePlatformError(w, err)
		return
	}
	s.auditPlatformAdmin(r, "platform.registration_mode.updated", "platform_setting", string(body.Mode), nil)
	writeJSON(w, http.StatusOK, map[string]string{"mode": string(body.Mode)})
}

func (s *Server) adminListPlatformUsers(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	items, err := store.ListPlatformUsers(r.Context())
	if err != nil {
		writePlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) adminUpdatePlatformUser(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	var body struct {
		Status string `json:"status"`
	}
	if !decodeJSON(w, r, 4<<10, &body) {
		return
	}
	cancelled, err := s.setPlatformUserStatus(r.Context(), r.PathValue("id"), body.Status)
	if err != nil {
		writePlatformError(w, err)
		return
	}
	s.auditPlatformAdmin(r, "platform.user.status_changed", "user", r.PathValue("id"), map[string]any{"status": body.Status, "cancelled_requests": cancelled})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cancelled_requests": cancelled})
}

// adminPlatformDevices is the PostgreSQL device authority used after the
// platform cutover.  It intentionally returns no MAC address, proof, public
// key or session token; administrators only need operational metadata to
// revoke a device.
func (s *Server) adminPlatformDevices(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	items, err := store.ListPlatformDevices(r.Context(), "")
	if err != nil {
		writePlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) adminRevokePlatformDevice(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	deviceID := strings.TrimSpace(r.PathValue("id"))
	if deviceID == "" {
		writeError(w, http.StatusNotFound, "device_not_found", "设备不存在或已经退出")
		return
	}
	if err := store.RevokePlatformDevice(r.Context(), deviceID, ""); err != nil {
		writeError(w, http.StatusNotFound, "device_not_found", "设备不存在或已经退出")
		return
	}
	cancelled, cancelErr := s.cancelPlatformDeviceRequests(r.Context(), deviceID)
	if cancelErr != nil {
		s.setSecurityRuntimeFailure("platform_admin_device_revoke_cancel", cancelErr)
	}
	s.auditPlatformAdmin(r, "agent.device.revoked", "device", deviceID, map[string]any{"cancelled_requests": cancelled})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cancelled_requests": cancelled})
}

func (s *Server) adminListPlatformInvitations(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	items, err := store.ListPlatformInvitations(r.Context())
	if err != nil {
		writePlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) adminCreatePlatformInvitation(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	var input PlatformInvitationInput
	if !decodeJSON(w, r, 32<<10, &input) {
		return
	}
	item, err := store.CreatePlatformInvitation(r.Context(), input)
	if err != nil {
		writePlatformError(w, err)
		return
	}
	s.auditPlatformAdmin(r, "platform.user_invitation.created", "user_invitation", item.ID, map[string]string{"role": input.RoleLabel})
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) adminRevokePlatformInvitation(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	if err := store.RevokePlatformInvitation(r.Context(), r.PathValue("id")); err != nil {
		writePlatformError(w, err)
		return
	}
	s.auditPlatformAdmin(r, "platform.user_invitation.revoked", "user_invitation", r.PathValue("id"), nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) adminDeletePlatformInvitation(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	if err := store.DeletePlatformInvitation(r.Context(), r.PathValue("id")); err != nil {
		writePlatformError(w, err)
		return
	}
	s.auditPlatformAdmin(r, "platform.user_invitation.deleted", "user_invitation", r.PathValue("id"), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminListPlatformAPIKeys(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	items, err := store.ListPlatformAPIKeys(r.Context())
	if err != nil {
		writePlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) adminCreatePlatformAPIKey(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	var input PlatformAPIKeyInput
	if !decodeJSON(w, r, 64<<10, &input) {
		return
	}
	item, plain, err := store.CreatePlatformAPIKey(r.Context(), input)
	if err != nil {
		writePlatformError(w, err)
		return
	}
	s.auditPlatformAdmin(r, "platform.api_key.created", "api_key", item.ID, map[string]string{"user_id": item.UserID, "label": item.Label})
	writeJSON(w, http.StatusCreated, map[string]any{"key": item, "plain_key": plain})
}

func (s *Server) adminCopyPlatformAPIKey(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	plain, err := store.CopyPlatformAPIKey(r.Context(), r.PathValue("id"))
	if err != nil {
		writePlatformError(w, err)
		return
	}
	s.auditPlatformAdmin(r, "platform.api_key.copied", "api_key", r.PathValue("id"), nil)
	writeJSON(w, http.StatusOK, map[string]string{"plain_key": plain})
}

func (s *Server) adminUpdatePlatformAPIKey(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	var body struct {
		Status string `json:"status"`
	}
	if !decodeJSON(w, r, 4<<10, &body) {
		return
	}
	cancelled, err := s.setPlatformAPIKeyStatus(r.Context(), r.PathValue("id"), body.Status)
	if err != nil {
		writePlatformError(w, err)
		return
	}
	s.auditPlatformAdmin(r, "platform.api_key.status_changed", "api_key", r.PathValue("id"), map[string]any{"status": body.Status, "cancelled_requests": cancelled})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cancelled_requests": cancelled})
}

func (s *Server) adminDeletePlatformAPIKey(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	cancelled, err := s.deletePlatformAPIKey(r.Context(), r.PathValue("id"))
	if err != nil {
		writePlatformError(w, err)
		return
	}
	s.auditPlatformAdmin(r, "platform.api_key.deleted", "api_key", r.PathValue("id"), map[string]any{"cancelled_requests": cancelled})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminReplacePlatformPlanVersion(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	var input PlanVersionInput
	if !decodeJSON(w, r, 64<<10, &input) {
		return
	}
	version, err := store.ReplaceCurrentPlanVersion(r.Context(), r.PathValue("code"), input)
	if err != nil {
		writePlatformError(w, err)
		return
	}
	s.auditPlatformAdmin(r, "plan.version.created", "plan", version.PlanID, map[string]any{"version": version.Version})
	writeJSON(w, http.StatusOK, version)
}

func (s *Server) adminListRoutePools(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	pools, err := store.ListRoutePools(r.Context())
	if err != nil {
		writePlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, pools)
}

func (s *Server) adminCreateRoutePool(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	var body struct {
		Name            string `json:"name"`
		SelectionPolicy string `json:"selection_policy"`
	}
	if !decodeJSON(w, r, 16<<10, &body) {
		return
	}
	pool, err := store.CreateRoutePool(r.Context(), DefaultPlatformTenantID(), body.Name, body.SelectionPolicy)
	if err != nil {
		writePlatformError(w, err)
		return
	}
	s.auditPlatformAdmin(r, "route_pool.created", "route_pool", pool.ID, map[string]any{"name": pool.Name})
	writeJSON(w, http.StatusCreated, pool)
}

func (s *Server) adminListProviderConnections(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	items, err := store.ListProviderConnections(r.Context())
	if err != nil {
		writePlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) adminCreateProviderConnection(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	var input ProviderConnectionInput
	if !decodeJSON(w, r, 1<<20, &input) {
		return
	}
	item, err := store.CreateProviderConnection(r.Context(), input)
	if err != nil {
		writePlatformError(w, err)
		return
	}
	s.auditPlatformAdmin(r, "provider_connection.created", "provider_connection", item.ID, map[string]any{"provider_name": item.ProviderName, "provider_kind": item.ProviderKind})
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) adminTestProviderConnection(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	result, err := store.TestProviderConnection(r.Context(), r.PathValue("id"))
	if err != nil {
		status := http.StatusUnprocessableEntity
		if errors.Is(err, ErrNotFound) {
			status = http.StatusNotFound
		}
		writeJSON(w, status, result)
		return
	}
	s.auditPlatformAdmin(r, "provider_connection.tested", "provider_connection", result.ConnectionID, map[string]any{"healthy": result.Healthy, "status_code": result.StatusCode})
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) adminUpdateProviderConnection(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	var body struct {
		Status string `json:"status"`
	}
	if !decodeJSON(w, r, 4<<10, &body) {
		return
	}
	if err := store.SetProviderConnectionStatus(r.Context(), r.PathValue("id"), body.Status); err != nil {
		writePlatformError(w, err)
		return
	}
	s.auditPlatformAdmin(r, "provider_connection.status_changed", "provider_connection", r.PathValue("id"), map[string]string{"status": body.Status})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) adminDeleteProviderConnection(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	if err := store.DeleteProviderConnection(r.Context(), r.PathValue("id")); err != nil {
		writePlatformError(w, err)
		return
	}
	s.auditPlatformAdmin(r, "provider_connection.deleted", "provider_connection", r.PathValue("id"), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminListUpstreamAccounts(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	items, err := store.ListUpstreamAccounts(r.Context(), r.URL.Query().Get("connection_id"))
	if err != nil {
		writePlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) adminCreateUpstreamAccount(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	var input UpstreamAccountInput
	if !decodeJSON(w, r, 1<<20, &input) {
		return
	}
	item, err := store.CreateUpstreamAccount(r.Context(), input)
	if err != nil {
		writePlatformError(w, err)
		return
	}
	s.auditPlatformAdmin(r, "upstream_account.created", "upstream_account", item.ID, map[string]any{"connection_id": item.ConnectionID, "label": item.Label})
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) adminSyncUpstreamAccountModels(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	items, err := store.SyncUpstreamAccountModels(r.Context(), r.PathValue("id"))
	if err != nil {
		writePlatformError(w, err)
		return
	}
	s.auditPlatformAdmin(r, "upstream_account.models_synced", "upstream_account", r.PathValue("id"), map[string]int{"models": len(items)})
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) adminListUpstreamAccountModels(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	items, err := store.ListUpstreamModelSnapshots(r.Context(), r.PathValue("id"))
	if err != nil {
		writePlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) adminUpdateUpstreamAccount(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	var body struct {
		Status string `json:"status"`
	}
	if !decodeJSON(w, r, 4<<10, &body) {
		return
	}
	if err := store.SetUpstreamAccountStatus(r.Context(), r.PathValue("id"), body.Status); err != nil {
		writePlatformError(w, err)
		return
	}
	s.auditPlatformAdmin(r, "upstream_account.status_changed", "upstream_account", r.PathValue("id"), map[string]string{"status": body.Status})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) adminDeleteUpstreamAccount(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	if err := store.DeleteUpstreamAccount(r.Context(), r.PathValue("id")); err != nil {
		writePlatformError(w, err)
		return
	}
	s.auditPlatformAdmin(r, "upstream_account.deleted", "upstream_account", r.PathValue("id"), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminAddRoutePoolMember(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	var input RoutePoolMemberInput
	if !decodeJSON(w, r, 32<<10, &input) {
		return
	}
	if err := store.AddRoutePoolMember(r.Context(), input); err != nil {
		writePlatformError(w, err)
		return
	}
	s.auditPlatformAdmin(r, "route_pool.member.upserted", "route_pool", input.RoutePoolID, map[string]any{"upstream_account_id": input.UpstreamAccountID})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) adminListRouteTargets(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	targets, err := store.ListRouteTargets(r.Context(), strings.TrimSpace(r.URL.Query().Get("model_id")))
	if err != nil {
		writePlatformError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, targets)
}

func (s *Server) adminCreateRouteTarget(w http.ResponseWriter, r *http.Request) {
	store := s.adminPlatformStore(w)
	if store == nil {
		return
	}
	var input ModelRouteTargetInput
	if !decodeJSON(w, r, 32<<10, &input) {
		return
	}
	target, err := store.CreateRouteTarget(r.Context(), input)
	if err != nil {
		writePlatformError(w, err)
		return
	}
	s.auditPlatformAdmin(r, "model_route_target.created", "model_route_target", target.ID, map[string]any{"model_id": target.ModelID, "upstream_model_id": target.UpstreamModelID})
	writeJSON(w, http.StatusCreated, target)
}

func writePlatformError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "platform_record_not_found", "目标记录不存在")
	case errors.Is(err, ErrProviderNotConfigured), errors.Is(err, ErrProviderProtocolSupport), errors.Is(err, ErrUnsafeProviderTarget):
		writeError(w, http.StatusUnprocessableEntity, "provider_not_ready", "上游连接尚未完成真实配置或不符合安全策略")
	case errors.Is(err, ErrPaymentProviderUnavailable):
		writeError(w, http.StatusUnprocessableEntity, "payment_not_ready", "支付商户连接器尚未完成真实验签与对账验证")
	case errors.Is(err, ErrInvalidPlatformModel), errors.Is(err, ErrInvalidPlan):
		writeError(w, http.StatusBadRequest, "invalid_platform_input", "提交的数据不符合平台配置规则")
	default:
		writeError(w, http.StatusInternalServerError, "platform_storage_failed", "统一数据存储操作失败")
	}
}
