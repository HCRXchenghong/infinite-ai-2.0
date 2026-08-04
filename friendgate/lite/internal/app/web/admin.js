const bootFallback = document.getElementById('boot-fallback');
function showBootFailure(detail) {
  if (!bootFallback) return;
  bootFallback.hidden = false;
  const detailNode = bootFallback.querySelector('[data-boot-detail]');
  if (detailNode) detailNode.textContent = detail || '请刷新页面；若仍无法打开，请确认本地 Vue 与 Element Plus 静态资源能够访问。';
}

if (!window.Vue || !window.ElementPlus) {
  showBootFailure('前端依赖加载失败。请检查 /vendor/vue.global.prod.js 和 /vendor/element-plus.full.min.js。');
  throw new Error('Infinite AI admin dependencies failed to load');
}

const { createApp, ref, reactive, computed, onMounted, onBeforeUnmount, watch } = Vue;
const { ElMessage, ElMessageBox } = ElementPlus;

try {
createApp({
  setup() {
    const bootstrapped = ref(false);
    const authenticated = ref(false);
    const setupRequired = ref(false);
    const setupStage = ref(0);
    const setupLoading = ref(false);
    const setupError = ref('');
    const username = ref('admin');
    const csrf = ref('');
    const tab = ref('dashboard');
    const systemPanel = ref('security');
    const loading = ref(false);
    const lastRefreshAt = ref(0);
    const refreshErrors = ref([]);
    const loginLoading = ref(false);
    const logoutLoading = ref(false);
    const inviteLoading = ref(false);
    const loginError = ref('');
    const dashboard = ref({});
    const accounts = ref([]);
    const accountModels = ref({ models: [], accounts: [], model_count: 0, updated_at: 0 });
    const keys = ref([]);
    const desktopUsers = ref([]);
    const desktopDevices = ref([]);
    const desktopPolicy = ref({});
    const invites = ref([]);
	const platform = reactive({ overview: {}, dashboard: {}, models: [], publications: [], plans: [], providers: [], upstreamAccounts: [], routePools: [], routeTargets: [], users: [], devices: [], wallets: [], paymentProviders: [], paymentOrders: [], apiKeys: [], usage: [], audits: [], invitations: [], registrationMode: '', error: '', loaded: false, loading: false });
    const bans = ref([]);
    const usage = ref([]);
    const logs = ref({ security: [], audit: [] });
    const usagePage = ref(1);
    const logPage = ref(1);
    const recordPageSize = 50;
    const inviteResult = ref(null);
    const inviteDialogVisible = ref(false);
    const banDialogVisible = ref(false);
    const banSaving = ref(false);
    const securitySaving = ref(false);
    const passwordSaving = ref(false);
	const security = ref({ config: {}, checks: [], health_percent: 0, nginx: {}, anomalies: [], runtime_errors: [] });
    const dataState = reactive({
      dashboard: { loaded: false, error: '' },
      bans: { loaded: false, error: '' },
      usage: { loaded: false, error: '' },
      logs: { loaded: false, error: '' },
      security: { loaded: false, error: '' },
      models: { loaded: false, error: '' }
    });
    const nowSeconds = ref(Math.floor(Date.now() / 1000));
    const accountDialogVisible = ref(false);
    const modelDialogVisible = ref(false);
    const modelRefreshing = ref(false);
    const manualAccountLoading = ref(false);
    const accountMethod = ref('oauth');
    const loginForm = reactive({ username: 'admin', password: '', totp_code: '' });
    const setupForm = reactive({ initialization_password: '', username: 'admin', password: '', confirm: '', totp_code: '' });
    const setupResult = reactive({ setup_token: '', secret: '', qr_data_url: '', otpauth_uri: '' });
    const oauthForm = reactive({ name: '' });
    const manualAccount = reactive({ name: '', auth: '' });
    const inviteForm = reactive({ role: '', recognition_code: '', quota_requests: 0, expires_hours: 168, binding_mode: 'ip' });
    const securityForm = reactive({ protection_enabled: null, nginx_protection: null, threshold_404: null, threshold_502: null, window_minutes: null, ban_hours: null });
    const banForm = reactive({ ip: '', reason: '', hours: 24, permanent: false });
    const passwordForm = reactive({ current_password: '', new_password: '', confirm: '', totp_code: '' });
    const backupExportDialogVisible = ref(false);
    const backupImportDialogVisible = ref(false);
    const backupExporting = ref(false);
    const backupImporting = ref(false);
    const backupExportForm = reactive({ passphrase: '', confirm: '' });
    const backupImportForm = reactive({ passphrase: '' });
    const backupImportFile = ref(null);
    const backupImportFiles = ref([]);
    const oauth = reactive({ sessionId: '', url: '', callbackURL: '', loading: false, completing: false });
    const keyQuotaDrafts = reactive({});
    const keyQuotaDirty = reactive({});
    const keyRowLoading = reactive({});
    const inviteRowLoading = reactive({});
    const accountRowLoading = reactive({});
    const desktopUserRowLoading = reactive({});
    const desktopDeviceRowLoading = reactive({});
    const desktopUserKeyDrafts = reactive({});
    const desktopUserKeyDirty = reactive({});
    const desktopPolicySaving = ref(false);
    const desktopPolicyForm = reactive({
      registration_enabled: true,
	  external_api_mode: 'authenticated_public',
      public_api_enabled: true,
      official_desktop_only: false,
      provider_name: 'Infinite AI',
      default_model: 'gpt-5.6',
      allowed_models: [],
      system_prompt: ''
    });
    const banRowLoading = reactive({});
    let loadSequence = 0;
    let pollTimer = 0;
    let dashboardLiveTimer = 0;
    let dashboardLiveInFlight = false;
    let clockTimer = 0;
    const mobileTabs = [
      { label: '仪表盘', value: 'dashboard' }, { label: '账号', value: 'accounts' },
      { label: '统一平台', value: 'platform' }, { label: '桌面用户', value: 'desktop' }, { label: '邀请', value: 'invitations' },
      { label: '密钥', value: 'keys' }, { label: '系统', value: 'system' }
    ];
    const validTabs = new Set(mobileTabs.map(item => item.value));
    const healthColors = [{ color: '#b85460', percentage: 60 }, { color: '#a87938', percentage: 85 }, { color: '#3a82ad', percentage: 100 }];

    const pageMeta = computed(() => ({
      dashboard: { title: '仪表盘', subtitle: '服务器资源、调用量与模型使用的最近同步概览' },
      accounts: { title: 'ChatGPT 账号', subtitle: 'OAuth 授权、真实额度同步与重置管理' },
      platform: { title: 'Infinite AI 统一平台', subtitle: 'PostgreSQL 平台模型、上游路由、用户、套餐与新 API Key 的真实配置' },
      desktop: { title: 'Infinite AI 用户', subtitle: '桌面登录、设备撤销、模型与系统提示词统一下发' },
      invitations: { title: '邀请管理', subtitle: '一次性邀请、识别码与领取状态' },
      keys: { title: 'API 密钥', subtitle: '密钥额度、设备与 IPv4 / IPv6 授权' },
      system: { title: '系统与记录', subtitle: '安全拦截、请求记录与后台操作审计' }
    }[tab.value]));

    const dashboardMetrics = computed(() => [
      { label: '今日调用', value: formatNumber(dashboard.value.requests_today || 0), note: '今日已透传请求' },
      { label: '记录内调用', value: formatNumber(dashboard.value.calls_total || 0), note: '当前保留的近 30 天记录' },
      { label: '有效密钥', value: formatNumber(dashboard.value.keys || 0), note: `全部 ${formatNumber(dashboard.value.keys_total || 0)} 个` },
      { label: '今日 Token', value: formatNumber(dashboard.value.tokens_today || 0), note: '上游响应 usage 汇总' },
      { label: '今日调用错误', value: formatNumber(dashboard.value.errors_today || 0), note: '使用记录中 HTTP 状态 ≥ 400' },
      { label: '可用账号', value: formatNumber(dashboard.value.accounts || 0), note: '当前启用的 OAuth 账号' },
      { label: '今日安全事件', value: formatNumber(dashboard.value.blocked_today || 0), note: '未授权、封禁与完整性记录' },
      { label: '当前封禁 IP', value: formatNumber(dashboard.value.bans || 0), note: '未过期的临时与永久黑名单' },
      { label: '已删除 Key', value: formatNumber(dashboard.value.keys_deleted || 0), note: '仅保留供历史使用记录关联的墓碑' }
    ]);

    const resourceCards = computed(() => {
      const system = dashboard.value.system || {};
      const cpu = system.cpu || {};
      const memory = system.memory || {};
      const storage = system.storage || {};
      return [
        { label: '服务器 CPU', available: cpu.available === true, percent: safePercent(cpu.percent), detail: cpu.available === true ? `${cpu.cores || 0} 核心` : '无法读取', note: cpu.available === true ? '宿主机最近采样' : (cpu.error || '指标不可用'), color: resourceColor(cpu.percent) },
        { label: '服务器内存', available: memory.available === true, percent: safePercent(memory.percent), detail: memory.available === true ? `${formatBytes(memory.used_bytes)} / ${formatBytes(memory.total_bytes)}` : '无法读取', note: memory.available === true ? '宿主机已用 / 总量' : (memory.error || '指标不可用'), color: resourceColor(memory.percent) },
        { label: '数据盘存储', available: storage.available === true, percent: safePercent(storage.percent), detail: storage.available === true ? `${formatBytes(storage.used_bytes)} / ${formatBytes(storage.total_bytes)}` : '无法读取', note: storage.available === true ? '数据目录所在文件系统' : (storage.error || '指标不可用'), color: resourceColor(storage.percent) }
      ];
    });
    const modelRanking = computed(() => dashboard.value.model_ranking || []);
    const quotaErrorCount = computed(() => accounts.value.filter(item => item.quota_error).length);
    const modelCatalogModels = computed(() => Array.isArray(accountModels.value.models) ? accountModels.value.models : []);
    const desktopKeyOptions = computed(() => keys.value.filter(item => item.status !== 'deleted'));
    const modelCatalogCount = computed(() => {
      const reported = Number(accountModels.value.model_count);
      return Number.isFinite(reported) && reported >= 0 ? reported : modelCatalogModels.value.length;
    });
    const modelAccountErrorCount = computed(() => (accountModels.value.accounts || []).filter(item => item.error).length);
    const maxModelCalls = computed(() => Math.max(1, ...modelRanking.value.map(item => Number(item.calls) || 0)));
    const combinedLogs = computed(() => [
      ...(logs.value.security || []).map(item => ({ time: item.created_at, type: `安全 · ${item.kind}`, actor: '系统', source_ip: item.ip || '—', target: item.path || '—', detail: item.detail || '' })),
      ...(logs.value.audit || []).map(item => ({ time: item.created_at, type: `操作 · ${item.action}`, actor: item.actor || 'admin', source_ip: item.ip || '—', target: item.target || '—', detail: item.detail || '' }))
    ].sort((a, b) => b.time - a.time).slice(0, 500));
	const pagedUsage = computed(() => usage.value.slice((usagePage.value - 1) * recordPageSize, usagePage.value * recordPageSize));
	const pagedLogs = computed(() => combinedLogs.value.slice((logPage.value - 1) * recordPageSize, logPage.value * recordPageSize));
	const runtimeErrorSummary = computed(() => (security.value.runtime_errors || []).map(item => `${item.key}（${when(item.updated_at)}）：${item.detail}`).join('；'));

    function normalizedTimestamp(value) {
      if (value === null || value === undefined || value === '') return 0;
      const numeric = Number(value);
      if (Number.isFinite(numeric) && numeric > 0) return numeric > 1e12 ? Math.floor(numeric / 1000) : Math.floor(numeric);
      const parsed = Date.parse(String(value));
      return Number.isFinite(parsed) ? Math.floor(parsed / 1000) : 0;
    }
    function normalizedModelID(value) {
      if (typeof value === 'string') return value.trim();
      if (value && typeof value === 'object') return String(value.id || value.model || value.name || '').trim();
      return '';
    }
    function normalizeAccountModels(payload) {
      const data = payload && typeof payload === 'object' ? payload : {};
      const sourceAccounts = Array.isArray(data.accounts) ? data.accounts : (Array.isArray(data.items) ? data.items : []);
      const normalizedAccounts = sourceAccounts.map(item => {
        const modelIDs = [...new Set((Array.isArray(item?.models) ? item.models : (Array.isArray(item?.model_ids) ? item.model_ids : [])).map(normalizedModelID).filter(Boolean))].sort((a, b) => a.localeCompare(b));
        return {
          account_id: item?.account_id ?? item?.id ?? '',
          account_name: String(item?.account_name || item?.name || item?.email || `账号 ${item?.account_id ?? item?.id ?? '—'}`),
          models: modelIDs,
          updated_at: normalizedTimestamp(item?.updated_at || item?.fetched_at),
          error: String(item?.error || item?.model_error || '')
        };
      });
      const modelMap = new Map();
      const topModels = Array.isArray(data.models) ? data.models : [];
      topModels.forEach(item => {
        const id = normalizedModelID(item);
        if (!id) return;
        const detail = item && typeof item === 'object' ? item : {};
        modelMap.set(id, { id, object: detail.object || '', owned_by: detail.owned_by || '' });
      });
      normalizedAccounts.forEach(item => item.models.forEach(id => { if (!modelMap.has(id)) modelMap.set(id, { id, object: '', owned_by: '' }); }));
      const models = [...modelMap.values()].sort((a, b) => a.id.localeCompare(b.id));
      const reportedCount = Number(data.model_count ?? data.total);
      return {
        models,
        accounts: normalizedAccounts,
        model_count: Number.isFinite(reportedCount) && reportedCount >= 0 ? reportedCount : models.length,
        updated_at: normalizedTimestamp(data.updated_at || data.fetched_at)
      };
    }
    function applyAccountModels(payload) { accountModels.value = normalizeAccountModels(payload); }
    function isAccountModelsPayload(payload) {
      return !!payload && typeof payload === 'object' && (Array.isArray(payload.models) || Array.isArray(payload.accounts) || Array.isArray(payload.items) || Object.prototype.hasOwnProperty.call(payload, 'model_count'));
    }
    function removeAccountModelSnapshot(account) {
      const targetIDs = new Set([account?.id, account?.chatgpt_account_id].filter(value => value !== null && value !== undefined && value !== '').map(String));
      const remainingAccounts = (accountModels.value.accounts || []).filter(item => !targetIDs.has(String(item.account_id)));
      const remainingModelIDs = new Set(remainingAccounts.flatMap(item => Array.isArray(item.models) ? item.models : []));
      const modelDetails = new Map((accountModels.value.models || []).map(item => [String(item.id), item]));
      const models = [...remainingModelIDs].sort((a, b) => a.localeCompare(b)).map(id => modelDetails.get(id) || { id, object: '', owned_by: '' });
      accountModels.value = { ...accountModels.value, accounts: remainingAccounts, models, model_count: models.length };
    }

    async function api(path, options = {}) {
	  const { timeoutMS = 35000, ...requestOptions } = options;
	  const headers = { ...(requestOptions.headers || {}) };
	  if (requestOptions.body) headers['Content-Type'] = 'application/json';
	  if (csrf.value && requestOptions.method && requestOptions.method !== 'GET') headers['X-CSRF-Token'] = csrf.value;
	  let timer = 0;
	  let controller = null;
	  if (!requestOptions.signal) {
		controller = new AbortController();
		requestOptions.signal = controller.signal;
		timer = window.setTimeout(() => controller.abort(), timeoutMS);
	  }
	  try {
		const response = await fetch(path, { credentials: 'same-origin', ...requestOptions, headers });
		let data = {};
		try { data = await response.json(); } catch {}
		if (response.status === 401 && authenticated.value && path !== '/api/login') {
		  expireAuthenticatedState();
		  throw new Error('登录已失效，请重新登录');
		}
		if (!response.ok) throw new Error(data?.error?.message || `请求失败 (${response.status})`);
		return data;
	  } catch (error) {
		if (controller && error?.name === 'AbortError') throw new Error(`操作超过 ${Math.round(timeoutMS / 1000)} 秒未响应；请刷新数据确认服务端最终状态`);
		throw error;
	  } finally {
		if (timer) window.clearTimeout(timer);
      }
    }

    async function rawAPI(path, options = {}, timeoutMS = 120000) {
      const controller = new AbortController();
      const timer = window.setTimeout(() => controller.abort(), timeoutMS);
      const headers = { ...(options.headers || {}) };
      if (csrf.value && options.method && options.method !== 'GET') headers['X-CSRF-Token'] = csrf.value;
      try {
        const response = await fetch(path, { credentials: 'same-origin', ...options, headers, signal: controller.signal });
        if (response.status === 401 && authenticated.value) {
          expireAuthenticatedState();
          throw new Error('登录已失效，请重新登录');
        }
        if (!response.ok) {
          let detail = '';
          try {
            const data = await response.clone().json();
            detail = data?.error?.message || data?.message || '';
          } catch {
            try { detail = (await response.text()).trim(); } catch {}
          }
          throw new Error(detail || `请求失败 (${response.status})`);
        }
        return response;
      } catch (error) {
        if (error?.name === 'AbortError') throw new Error(`操作超过 ${Math.round(timeoutMS / 1000)} 秒未响应；请稍后重试`);
        throw error;
      } finally {
        window.clearTimeout(timer);
      }
    }

    async function apiWithTimeout(path, options = {}, timeoutMS = 25000) {
      const controller = new AbortController();
      const timer = window.setTimeout(() => controller.abort(), timeoutMS);
      try {
        return await api(path, { ...options, signal: controller.signal });
      } catch (error) {
        if (error?.name === 'AbortError') throw new Error(`请求超过 ${Math.round(timeoutMS / 1000)} 秒未响应`);
        throw error;
      } finally {
        window.clearTimeout(timer);
      }
    }

    function message(text, type = 'success') { ElMessage({ message: text, type, plain: true, grouping: true }); }
    function formatNumber(value) { return new Intl.NumberFormat('zh-CN').format(Number(value) || 0); }
    function adminPasswordBytes(value) { return new TextEncoder().encode(String(value || '')).byteLength; }
    function validAdminPassword(value) { const size = adminPasswordBytes(value); return size >= 12 && size <= 256; }
    function backupPassphraseBytes(value) { return new TextEncoder().encode(String(value || '')).byteLength; }
    function validBackupPassphrase(value) { const size = backupPassphraseBytes(value); return size >= 12 && size <= 4096; }
    function formatBytes(value) { const bytes = Number(value) || 0; if (!bytes) return '0 B'; const units = ['B','KB','MB','GB','TB']; const index = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024))); return `${(bytes / (1024 ** index)).toFixed(index > 2 ? 1 : 0)} ${units[index]}`; }
    function safePercent(value) { return Math.max(0, Math.min(100, Number(value) || 0)); }
    function resourceColor(value) { const percent = safePercent(value); return percent >= 90 ? '#b85460' : percent >= 75 ? '#a87938' : '#3a82ad'; }
    function modelRankPercent(value) { return Math.round((Number(value) || 0) * 100 / maxModelCalls.value); }
    function when(value) {
      if (value === null || value === undefined || value === '') return '—';
      const numeric = Number(value);
      const date = Number.isFinite(numeric)
        ? new Date(Math.abs(numeric) < 100000000000 ? numeric * 1000 : numeric)
        : new Date(value);
      return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString('zh-CN');
    }
    function hasQuota(account, field) {
      if (!account || !(Number(account.quota_updated_at) > 0)) return false;
      const value = Number(account[field]);
      return Number.isFinite(value) && value >= 0;
    }
    function quotaPercent(value) { return safePercent(value); }
    function quotaText(value) { const percent = quotaPercent(value); return `${percent.toFixed(percent % 1 ? 1 : 0)}%`; }
    function quotaColor(value) { return resourceColor(value); }
    function resetText(value) {
      if (!value) return '重置时间未知';
      const seconds = Math.max(0, value - Math.floor(Date.now() / 1000));
      if (!seconds) return `正在重置 · ${when(value)}`;
      const days = Math.floor(seconds / 86400), hours = Math.floor((seconds % 86400) / 3600), minutes = Math.floor((seconds % 3600) / 60);
      const left = days ? `${days}天 ${hours}小时` : hours ? `${hours}小时 ${minutes}分` : `${minutes}分`;
      return `${left}后 · ${when(value)}`;
    }
    function inviteStatus(invite) { return invite.status === 'pending' && invite.expires_at <= nowSeconds.value ? 'expired' : invite.status; }
    function inviteStatusLabel(invite) { return ({ pending: '待领取', claimed: '已使用', revoked: '已撤销', expired: '已过期' })[inviteStatus(invite)] || invite.status; }
    function inviteTag(status) { return status === 'claimed' ? 'success' : status === 'pending' ? 'warning' : status === 'revoked' ? 'danger' : 'info'; }
    function nginxStateText(value) {
      const nginx = value || {};
      if (nginx.state === 'not_installed_or_not_mounted') return '当前环境未安装或未挂载 Nginx（不适用）';
      if (nginx.state === 'permission_denied') return 'Nginx 配置存在，但当前进程无读取权限';
      if (nginx.state === 'baseline_outdated') return '指纹算法已升级，需要管理员重新确认基线';
      if (nginx.available && !nginx.baseline_set) return `已读取 ${nginx.file_count || 0} 个文件，尚未确认基线`;
      if (nginx.available) return `已读取 ${nginx.file_count || 0} 个文件`;
      return 'Nginx 完整性快照当前不可用';
    }
    function base64url(value) { const bytes = new TextEncoder().encode(value); let binary = ''; bytes.forEach(byte => { binary += String.fromCharCode(byte); }); return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', ''); }

    function clearReactiveObject(target) { Object.keys(target).forEach(key => { delete target[key]; }); }
    function resetSetupSecrets() { Object.assign(setupResult, { setup_token: '', secret: '', qr_data_url: '', otpauth_uri: '' }); setupForm.initialization_password = ''; setupForm.password = ''; setupForm.confirm = ''; setupForm.totp_code = ''; }
    function resetAuthenticatedData() {
      accountDialogVisible.value = false;
      modelDialogVisible.value = false;
      inviteDialogVisible.value = false;
      banDialogVisible.value = false;
      backupExportDialogVisible.value = false;
      backupImportDialogVisible.value = false;
      inviteLoading.value = false;
      logoutLoading.value = false;
      banSaving.value = false;
      manualAccountLoading.value = false;
      securitySaving.value = false;
      passwordSaving.value = false;
      modelRefreshing.value = false;
      backupExporting.value = false;
      backupImporting.value = false;
      resetAccountDialog();
      resetInviteDialog();
      resetBackupExportDialog();
      resetBackupImportDialog();
      Object.assign(banForm, { ip: '', reason: '', hours: 24, permanent: false });
      Object.assign(passwordForm, { current_password: '', new_password: '', confirm: '', totp_code: '' });
      loginForm.password = '';
      loginForm.totp_code = '';
      dashboard.value = {};
      accounts.value = [];
      accountModels.value = { models: [], accounts: [], model_count: 0, updated_at: 0 };
      keys.value = [];
      desktopUsers.value = [];
      desktopDevices.value = [];
      desktopPolicy.value = {};
      invites.value = [];
      bans.value = [];
      usage.value = [];
      logs.value = { security: [], audit: [] };
	  usagePage.value = 1;
	  logPage.value = 1;
	  security.value = { config: {}, checks: [], health_percent: 0, nginx: {}, anomalies: [], runtime_errors: [] };
      Object.values(dataState).forEach(state => { state.loaded = false; state.error = ''; });
      Object.assign(securityForm, { protection_enabled: null, nginx_protection: null, threshold_404: null, threshold_502: null, window_minutes: null, ban_hours: null });
      refreshErrors.value = [];
      lastRefreshAt.value = 0;
      clearReactiveObject(keyQuotaDrafts);
      clearReactiveObject(keyQuotaDirty);
      clearReactiveObject(keyRowLoading);
      clearReactiveObject(inviteRowLoading);
      clearReactiveObject(accountRowLoading);
      clearReactiveObject(desktopUserRowLoading);
      clearReactiveObject(desktopDeviceRowLoading);
      clearReactiveObject(desktopUserKeyDrafts);
      clearReactiveObject(desktopUserKeyDirty);
      clearReactiveObject(banRowLoading);
      try { ElMessageBox.close(); } catch {}
    }
    function expireAuthenticatedState() {
      authenticated.value = false;
      csrf.value = '';
      loading.value = false;
      loadSequence += 1;
      resetAuthenticatedData();
    }
    function syncKeyQuotaDrafts(items) {
      const currentIDs = new Set(items.map(item => String(item.id)));
      items.forEach(item => {
        const id = String(item.id);
        if (!Object.prototype.hasOwnProperty.call(keyQuotaDrafts, id) || !keyQuotaDirty[id]) {
          keyQuotaDrafts[id] = Number(item.quota_requests) || 0;
          keyQuotaDirty[id] = false;
        } else {
          keyQuotaDirty[id] = Number(keyQuotaDrafts[id]) !== Number(item.quota_requests);
        }
      });
      Object.keys(keyQuotaDrafts).forEach(id => { if (!currentIDs.has(id)) { delete keyQuotaDrafts[id]; delete keyQuotaDirty[id]; delete keyRowLoading[id]; } });
    }
    function markKeyQuotaDirty(key) { keyQuotaDirty[String(key.id)] = Number(keyQuotaDrafts[String(key.id)]) !== Number(key.quota_requests); }
    function isKeyQuotaDirty(key) { return !!keyQuotaDirty[String(key.id)]; }
    function setKeyRowLoading(key, action = '') { if (action) keyRowLoading[String(key.id)] = action; else delete keyRowLoading[String(key.id)]; }
    function setInviteRowLoading(invite, action = '') { if (action) inviteRowLoading[String(invite.id)] = action; else delete inviteRowLoading[String(invite.id)]; }
    function setAccountRowLoading(account, action = '') { if (action) accountRowLoading[String(account.id)] = action; else delete accountRowLoading[String(account.id)]; }
    function syncDesktopUserDrafts(items) {
      const currentIDs = new Set(items.map(item => String(item.id)));
      items.forEach(item => {
        const id = String(item.id);
        if (!Object.prototype.hasOwnProperty.call(desktopUserKeyDrafts, id) || !desktopUserKeyDirty[id]) {
          desktopUserKeyDrafts[id] = Number(item.api_key_id) || 0;
          desktopUserKeyDirty[id] = false;
        } else {
          desktopUserKeyDirty[id] = Number(desktopUserKeyDrafts[id]) !== Number(item.api_key_id || 0);
        }
      });
      Object.keys(desktopUserKeyDrafts).forEach(id => {
        if (!currentIDs.has(id)) {
          delete desktopUserKeyDrafts[id];
          delete desktopUserKeyDirty[id];
          delete desktopUserRowLoading[id];
        }
      });
    }
    function markDesktopUserKeyDirty(user) { desktopUserKeyDirty[String(user.id)] = Number(desktopUserKeyDrafts[String(user.id)]) !== Number(user.api_key_id || 0); }
    function applyDesktopPolicy(payload) {
      const value = payload && typeof payload === 'object' ? payload : {};
      desktopPolicy.value = value;
      Object.assign(desktopPolicyForm, {
        registration_enabled: value.registration_enabled !== false,
		external_api_mode: String(value.external_api_mode || 'authenticated_public'),
        public_api_enabled: value.public_api_enabled !== false,
        official_desktop_only: value.official_desktop_only === true,
        provider_name: String(value.provider_name || 'Infinite AI'),
        default_model: String(value.default_model || 'gpt-5.6'),
        allowed_models: Array.isArray(value.allowed_models) ? [...value.allowed_models] : [],
        system_prompt: String(value.system_prompt || '')
      });
    }
    function setBanRowLoading(item, active) { if (active) banRowLoading[item.ip] = true; else delete banRowLoading[item.ip]; }
	async function refreshBanListAfterMutation() {
	  try {
		const data = await apiWithTimeout('/api/system/bans');
		bans.value = data.items || [];
		dataState.bans.loaded = true;
		dataState.bans.error = '';
		dashboard.value.bans = bans.value.length;
		return true;
	  } catch (error) {
		dataState.bans.error = error.message || '读取失败';
		message(`操作已生效，但黑名单列表刷新失败：${error.message || '请稍后手动刷新'}`, 'warning');
		return false;
	  }
	}

    function applyDashboardData(data) {
      dashboard.value = data || {};
    }
    function applyUsageData(data) {
      usage.value = data.items || [];
      usagePage.value = Math.min(usagePage.value, Math.max(1, Math.ceil(usage.value.length / recordPageSize)));
    }
    async function refreshDashboardLive(options = {}) {
      if (!authenticated.value || document.hidden || tab.value !== 'dashboard') return;
      if (dashboardLiveInFlight) return;
      if (loading.value && options.force !== true) return;
      dashboardLiveInFlight = true;
      const endpoints = [
        { name: '仪表盘', state: 'dashboard', path: '/api/dashboard', apply: applyDashboardData },
        { name: '使用记录', state: 'usage', path: '/api/system/usage?limit=20', apply: applyUsageData }
      ];
      try {
        const results = await Promise.allSettled(endpoints.map(endpoint => apiWithTimeout(endpoint.path, {}, 8000).then(data => {
          if (authenticated.value && tab.value === 'dashboard') {
            endpoint.apply(data);
            dataState[endpoint.state].loaded = true;
            dataState[endpoint.state].error = '';
          }
        }).catch(error => {
          if (authenticated.value && tab.value === 'dashboard') dataState[endpoint.state].error = error.message || '读取失败';
          throw error;
        })));
        if (!authenticated.value || tab.value !== 'dashboard') return;
        const errors = [];
        let successCount = 0;
        results.forEach((result, index) => {
          if (result.status === 'fulfilled') successCount += 1;
          else errors.push(`${endpoints[index].name}：${result.reason?.message || '读取失败'}`);
        });
        nowSeconds.value = Math.floor(Date.now() / 1000);
        if (successCount > 0) lastRefreshAt.value = nowSeconds.value;
        refreshErrors.value = errors;
      } finally {
        dashboardLiveInFlight = false;
      }
    }

    async function loadAll(options = {}) {
      if (!authenticated.value) return;
      const silent = options?.silent === true;
      const sequence = ++loadSequence;
      if (!silent) loading.value = true;
      const endpoints = [
        { name: '仪表盘', state: 'dashboard', path: '/api/dashboard', apply: applyDashboardData },
        { name: '账号', path: '/api/accounts', apply: data => { accounts.value = data.items || []; } },
        { name: '模型目录', state: 'models', path: '/api/accounts/models', apply: applyAccountModels },
        { name: 'API 密钥', path: '/api/keys', apply: data => { const items = data.items || []; keys.value = items; syncKeyQuotaDrafts(items); } },
        { name: '桌面用户', path: '/api/desktop/users', apply: data => { const items = data.items || []; desktopUsers.value = items; syncDesktopUserDrafts(items); } },
        { name: '桌面设备', path: '/api/desktop/devices', apply: data => { desktopDevices.value = data.items || []; } },
        { name: '桌面策略', path: '/api/desktop/policy', apply: applyDesktopPolicy },
        { name: '邀请', path: '/api/invitations', apply: data => { invites.value = data.items || []; } },
        { name: 'IP 黑名单', state: 'bans', path: '/api/system/bans', apply: data => { bans.value = data.items || []; } },
        { name: '使用记录', state: 'usage', path: '/api/system/usage', apply: applyUsageData },
        { name: '安全与操作日志', state: 'logs', path: '/api/system/logs', apply: data => { logs.value = data || { security: [], audit: [] }; logPage.value = Math.min(logPage.value, Math.max(1, Math.ceil(combinedLogs.value.length / recordPageSize))); } },
        { name: '安全状态', state: 'security', path: '/api/system/security', apply: data => { security.value = data || security.value; Object.assign(securityForm, security.value.config || {}); } }
      ];
	  const results = await Promise.allSettled(endpoints.map(endpoint => apiWithTimeout(endpoint.path).then(data => {
		if (sequence === loadSequence && authenticated.value) {
		  endpoint.apply(data);
		  if (endpoint.state) {
			dataState[endpoint.state].loaded = true;
			dataState[endpoint.state].error = '';
		  }
		}
		return data;
	  }).catch(error => {
		if (sequence === loadSequence && authenticated.value && endpoint.state) dataState[endpoint.state].error = error.message || '读取失败';
		throw error;
	  })));
      if (sequence !== loadSequence || !authenticated.value) {
        if (sequence === loadSequence) loading.value = false;
        return;
      }
      const errors = [];
      let successCount = 0;
	  results.forEach((result, index) => {
		if (result.status === 'fulfilled') {
		  successCount += 1;
        } else {
          errors.push(`${endpoints[index].name}：${result.reason?.message || '读取失败'}`);
        }
      });
      nowSeconds.value = Math.floor(Date.now() / 1000);
      refreshErrors.value = errors;
      if (successCount > 0) lastRefreshAt.value = nowSeconds.value;
      if (errors.length && !silent) message(`部分数据未更新（${errors.length} 项），旧数据已保留`, 'warning');
      loading.value = false;
    }

    async function loadPlatform(options = {}) {
      if (!authenticated.value || platform.loading) return;
      platform.loading = true;
      if (!options.silent) platform.error = '';
      const endpoints = [
        ['overview', '/api/platform/overview'], ['dashboard', '/api/platform/dashboard'], ['models', '/api/platform/models'], ['publications', '/api/platform/model-publications'],
        ['plans', '/api/platform/plans'], ['providers', '/api/platform/providers'], ['upstreamAccounts', '/api/platform/upstream-accounts'],
		['routePools', '/api/platform/route-pools'], ['routeTargets', '/api/platform/route-targets'], ['users', '/api/platform/users'], ['devices', '/api/platform/devices'],
        ['wallets', '/api/platform/wallets'], ['paymentProviders', '/api/platform/payments/providers'], ['paymentOrders', '/api/platform/payments/orders?limit=100'], ['apiKeys', '/api/platform/api-keys'], ['usage', '/api/platform/usage?limit=100'],
        ['audits', '/api/platform/audits?limit=100'], ['invitations', '/api/platform/user-invitations'], ['registration', '/api/platform/settings/registration']
      ];
      const results = await Promise.allSettled(endpoints.map(([name, path]) => apiWithTimeout(path, {}, 15000)));
      const failure = results.find(item => item.status === 'rejected');
      if (failure) {
        platform.error = failure.reason?.message || '统一平台数据读取失败';
        platform.loaded = true;
        platform.loading = false;
        return;
      }
      const values = Object.fromEntries(endpoints.map(([name], index) => [name, results[index].value]));
      platform.overview = values.overview || {};
	  platform.dashboard = values.dashboard || {};
      platform.models = Array.isArray(values.models) ? values.models : [];
      platform.publications = Array.isArray(values.publications) ? values.publications : [];
      platform.plans = Array.isArray(values.plans) ? values.plans : [];
      platform.providers = Array.isArray(values.providers) ? values.providers : [];
      platform.upstreamAccounts = Array.isArray(values.upstreamAccounts) ? values.upstreamAccounts : [];
      platform.routePools = Array.isArray(values.routePools) ? values.routePools : [];
      platform.routeTargets = Array.isArray(values.routeTargets) ? values.routeTargets : [];
      platform.users = Array.isArray(values.users) ? values.users : [];
	  platform.devices = Array.isArray(values.devices?.items) ? values.devices.items : [];
	  platform.wallets = Array.isArray(values.wallets) ? values.wallets : [];
	  platform.paymentProviders = Array.isArray(values.paymentProviders) ? values.paymentProviders : [];
	  platform.paymentOrders = Array.isArray(values.paymentOrders) ? values.paymentOrders : [];
      platform.apiKeys = Array.isArray(values.apiKeys) ? values.apiKeys : [];
	  platform.usage = Array.isArray(values.usage) ? values.usage : [];
	  platform.audits = Array.isArray(values.audits) ? values.audits : [];
	  platform.invitations = Array.isArray(values.invitations) ? values.invitations : [];
      platform.registrationMode = String(values.registration?.mode || '');
      platform.error = '';
      platform.loaded = true;
      platform.loading = false;
    }

    async function platformPrompt(title, message, options = {}) {
      const result = await ElMessageBox.prompt(message, title, { confirmButtonText: '继续', cancelButtonText: '取消', inputValue: options.value || '', inputPlaceholder: options.placeholder || '', inputType: options.password ? 'password' : 'text', inputValidator: value => options.optional || String(value || '').trim() ? true : '此项不能为空' });
      return String(result.value || '').trim();
    }
    async function createPlatformModel() {
      try {
        const model_key = await platformPrompt('创建平台模型', '稳定模型标识（例如 infinite-pro）', { placeholder: 'infinite-pro' });
        const display_name = await platformPrompt('创建平台模型', '用户侧显示名称', { placeholder: 'Infinite Pro' });
        const category = await platformPrompt('创建平台模型', '类别：chat、image、audio、embedding 或 multimodal', { value: 'chat' });
        await api('/api/platform/models', { method: 'POST', body: JSON.stringify({ model_key, display_name, category, description: '', capabilities: {}, billing: {}, status: 'active' }) });
        message('平台模型已创建'); await loadPlatform({ silent: true });
      } catch (error) { if (error !== 'cancel') message(error.message || '已取消创建', 'error'); }
    }
    async function publishPlatformModel() {
      try {
        const model_id = await platformPrompt('发布平台模型', '平台模型 ID（可从下方模型表复制）');
        const product_scope = await platformPrompt('发布平台模型', '产品范围：chat、agent 或 external_api', { value: 'chat' });
        const protocol = await platformPrompt('发布平台模型', '协议：responses、chat_completions、messages 或 generate_content', { value: 'responses' });
        await api('/api/platform/model-publications', { method: 'PUT', body: JSON.stringify({ model_id, product_scope, protocol, enabled: true, default_for_scope: false, plan_rules: {} }) });
        message('模型发布配置已保存'); await loadPlatform({ silent: true });
      } catch (error) { if (error !== 'cancel') message(error.message || '已取消发布', 'error'); }
    }
    async function createPlatformProvider() {
      try {
        const provider_name = await platformPrompt('添加兼容上游', '连接名称（小写字母、数字、连字符）', { placeholder: 'provider-a' });
        const provider_kind = await platformPrompt('添加兼容上游', '类型：openai_compatible、anthropic_compatible 或 gemini_compatible', { value: 'openai_compatible' });
        const base_url = await platformPrompt('添加兼容上游', '兼容 Base URL（例如 https://api.example.com/v1）', { placeholder: 'https://api.example.com/v1' });
        const credential = await platformPrompt('添加兼容上游', '上游 API Key（仅加密保存）', { password: true });
        await api('/api/platform/providers', { method: 'POST', body: JSON.stringify({ provider_kind, provider_name, base_url, credential, settings: {}, status: 'active' }) });
        message('兼容上游已保存；请在账号列表创建账号并同步模型'); await loadPlatform({ silent: true });
      } catch (error) { if (error !== 'cancel') message(error.message || '已取消添加', 'error'); }
    }
    async function createPlatformRoutePool() {
      try {
        const name = await platformPrompt('创建路由池', '路由池名称', { placeholder: 'primary-pool' });
        await api('/api/platform/route-pools', { method: 'POST', body: JSON.stringify({ name, selection_policy: 'quota_aware' }) });
        message('路由池已创建'); await loadPlatform({ silent: true });
      } catch (error) { if (error !== 'cancel') message(error.message || '已取消创建', 'error'); }
    }
    async function createPlatformAPIKey() {
      try {
        const user_id = await platformPrompt('创建新 API Key', '用户 ID（可从下方用户表复制）');
        const model_id = await platformPrompt('创建新 API Key', '允许的平台模型 ID');
        const label = await platformPrompt('创建新 API Key', 'Key 备注');
        const created = await api('/api/platform/api-keys', { method: 'POST', body: JSON.stringify({ user_id, label, scopes: [{ product_scope: 'external_api', model_id }], ip_policy: { mode: 'unrestricted' }, device_policy: { mode: 'unrestricted' } }) });
        await navigator.clipboard.writeText(created.plain_key);
        message('新 Key 已创建并复制到剪贴板；请立即安全保存'); await loadPlatform({ silent: true });
      } catch (error) { if (error !== 'cancel') message(error.message || '已取消创建', 'error'); }
    }
    async function togglePlatformKey(item) {
      const status = item.status === 'active' ? 'disabled' : 'active';
      try { await api(`/api/platform/api-keys/${item.id}`, { method: 'PATCH', body: JSON.stringify({ status }) }); message(status === 'active' ? 'Key 已启用' : 'Key 已停用，并已取消在途请求'); await loadPlatform({ silent: true }); }
      catch (error) { message(error.message, 'error'); }
    }
    async function copyPlatformKey(item) {
      try { const result = await api(`/api/platform/api-keys/${item.id}/copy`, { method: 'POST', body: '{}' }); await navigator.clipboard.writeText(result.plain_key); message('Key 已复制到剪贴板'); }
      catch (error) { message(error.message, 'error'); }
    }
    async function deletePlatformKey(item) {
      try {
        await ElMessageBox.confirm(`确定删除新 API Key“${item.label}”？删除会立即取消在途请求，密文不可恢复。`, '删除新 API Key', { type: 'error', confirmButtonText: '删除', cancelButtonText: '取消' });
        await api(`/api/platform/api-keys/${item.id}`, { method: 'DELETE' }); message('Key 已删除，并已取消在途请求'); await loadPlatform({ silent: true });
      } catch (error) { if (error !== 'cancel' && error !== 'close') message(error.message || '删除失败', 'error'); }
    }
    async function createPlatformUpstreamAccount() {
      try {
        const connection_id = await platformPrompt('创建上游账号', '连接 ID（从上游连接表复制）');
        const label = await platformPrompt('创建上游账号', '账号备注', { placeholder: '主账号 A' });
        const credential = await platformPrompt('创建上游账号', '账号专属 API Key（留空时使用连接凭证）', { password: true, optional: true });
        await api('/api/platform/upstream-accounts', { method: 'POST', body: JSON.stringify({ connection_id, label, credential, external_reference: label, model_catalog: [], quota_state: {}, status: 'active' }) });
        message('上游账号已创建，请同步模型后再添加到路由池'); await loadPlatform({ silent: true });
      } catch (error) { if (error !== 'cancel') message(error.message || '已取消创建', 'error'); }
    }
    async function syncPlatformAccountModels(item) {
      try { const models = await api(`/api/platform/upstream-accounts/${item.id}/models/sync`, { method: 'POST', body: '{}' }); message(`已同步 ${Array.isArray(models) ? models.length : 0} 个上游模型`); await loadPlatform({ silent: true }); }
      catch (error) { message(error.message || '模型同步失败', 'error'); }
    }
    async function togglePlatformProvider(item) {
      const status = item.status === 'active' ? 'disabled' : 'active';
      try { await api(`/api/platform/providers/${item.id}`, { method: 'PATCH', body: JSON.stringify({ status }) }); message(status === 'active' ? '上游连接已启用' : '上游连接已停用'); await loadPlatform({ silent: true }); }
      catch (error) { message(error.message || '操作失败', 'error'); }
    }
    async function testPlatformProvider(item) {
      try { const result = await api(`/api/platform/providers/${item.id}/health`, { method: 'POST', body: '{}' }); message(result.healthy ? `连接正常（HTTP ${result.status_code}）` : (result.error || '连接测试失败'), result.healthy ? 'success' : 'warning'); await loadPlatform({ silent: true }); }
      catch (error) { message(error.message || '连接测试失败', 'error'); }
    }
    async function deletePlatformProvider(item) {
      try { await ElMessageBox.confirm(`删除上游连接“${item.provider_name}”？其账号会一起删除，并立即移出路由。`, '删除上游连接', { type: 'error', confirmButtonText: '删除', cancelButtonText: '取消' }); await api(`/api/platform/providers/${item.id}`, { method: 'DELETE' }); message('上游连接已删除'); await loadPlatform({ silent: true }); }
      catch (error) { if (error !== 'cancel' && error !== 'close') message(error.message || '删除失败', 'error'); }
    }
    async function togglePlatformUpstreamAccount(item) {
      const status = item.status === 'active' ? 'disabled' : 'active';
      try { await api(`/api/platform/upstream-accounts/${item.id}`, { method: 'PATCH', body: JSON.stringify({ status }) }); message(status === 'active' ? '上游账号已启用' : '上游账号已停用并立即退出调度'); await loadPlatform({ silent: true }); }
      catch (error) { message(error.message || '操作失败', 'error'); }
    }
    async function deletePlatformUpstreamAccount(item) {
      try { await ElMessageBox.confirm(`删除上游账号“${item.label}”？该账号会立即从所有路由池中移除。`, '删除上游账号', { type: 'error', confirmButtonText: '删除', cancelButtonText: '取消' }); await api(`/api/platform/upstream-accounts/${item.id}`, { method: 'DELETE' }); message('上游账号已删除'); await loadPlatform({ silent: true }); }
      catch (error) { if (error !== 'cancel' && error !== 'close') message(error.message || '删除失败', 'error'); }
    }
    async function addPlatformRoutePoolMember() {
      try {
        const route_pool_id = await platformPrompt('添加路由池成员', '路由池 ID');
        const upstream_account_id = await platformPrompt('添加路由池成员', '上游账号 ID');
        await api('/api/platform/route-pool-members', { method: 'POST', body: JSON.stringify({ route_pool_id, upstream_account_id, priority: 100, weight: 100, enabled: true }) });
        message('账号已加入路由池'); await loadPlatform({ silent: true });
      } catch (error) { if (error !== 'cancel') message(error.message || '操作失败', 'error'); }
    }
    async function createPlatformRouteTarget() {
      try {
        const model_id = await platformPrompt('创建路由目标', '平台模型 ID');
        const route_pool_id = await platformPrompt('创建路由目标', '路由池 ID');
        const upstream_model_id = await platformPrompt('创建路由目标', '上游私有模型 ID');
        const product_scope = await platformPrompt('创建路由目标', '产品范围：chat、agent 或 external_api', { value: 'chat' });
        const protocol = await platformPrompt('创建路由目标', '协议：responses、chat_completions、messages 或 generate_content', { value: 'responses' });
        await api('/api/platform/route-targets', { method: 'POST', body: JSON.stringify({ model_id, route_pool_id, upstream_model_id, product_scope, protocol, priority: 100, enabled: true }) });
        message('路由目标已创建'); await loadPlatform({ silent: true });
      } catch (error) { if (error !== 'cancel') message(error.message || '操作失败', 'error'); }
    }
    async function setPlatformRegistrationMode() {
      try {
        const mode = await platformPrompt('用户注册策略', 'closed、invite_only 或 public', { value: platform.registrationMode || 'invite_only' });
        await api('/api/platform/settings/registration', { method: 'PUT', body: JSON.stringify({ mode }) }); message('注册策略已立即生效'); await loadPlatform({ silent: true });
      } catch (error) { if (error !== 'cancel') message(error.message || '保存失败', 'error'); }
    }
    async function updatePlatformPlan(item) {
      try {
        const current = item.current || {};
        const price = await platformPrompt(`编辑 ${item.display_name}`, '月价最小货币单位（例如 USD 分）', { value: String(current.monthly_price_minor || 0) });
        const chatMonthly = await platformPrompt(`编辑 ${item.display_name}`, 'Chat 每月 Token', { value: String(current.chat_monthly_tokens || 0) });
        const agentMonthly = await platformPrompt(`编辑 ${item.display_name}`, 'Agent 每月 Token', { value: String(current.agent_monthly_tokens || 0) });
        const chatRolling = await platformPrompt(`编辑 ${item.display_name}`, 'Chat 五小时 Token', { value: String(current.chat_rolling_5h_tokens || 0) });
        const agentRolling = await platformPrompt(`编辑 ${item.display_name}`, 'Agent 五小时 Token', { value: String(current.agent_rolling_5h_tokens || 0) });
        const numeric = [price, chatMonthly, agentMonthly, chatRolling, agentRolling].map(value => Number(value));
        if (numeric.some(value => !Number.isSafeInteger(value) || value < 0)) throw new Error('所有价格和额度都必须是非负整数');
        await ElMessageBox.confirm('这会创建新的套餐版本，仅影响之后创建或续期的套餐；现有账本不会被改写。', `确认更新 ${item.display_name}`, { type: 'warning', confirmButtonText: '创建新版本', cancelButtonText: '取消' });
        await api(`/api/platform/plans/${encodeURIComponent(item.code)}/version`, { method: 'PUT', body: JSON.stringify({ currency: current.currency || 'USD', monthly_price_minor: numeric[0], chat_monthly_tokens: numeric[1], agent_monthly_tokens: numeric[2], chat_rolling_5h_tokens: numeric[3], agent_rolling_5h_tokens: numeric[4], entitlements: current.entitlements || {}, model_rules: current.model_rules || {} }) });
        message('套餐新版本已生效于后续分配'); await loadPlatform({ silent: true });
      } catch (error) { if (error !== 'cancel' && error !== 'close') message(error.message || '套餐更新失败', 'error'); }
    }
    async function createPlatformUserInvitation() {
      try {
        const role_label = await platformPrompt('新建用户邀请', '角色或备注名称', { placeholder: '王同学' });
        const expiresHours = await platformPrompt('新建用户邀请', '有效时长（小时）', { value: '168' });
        const hours = Number(expiresHours);
        if (!Number.isFinite(hours) || hours < 1 || hours > 8760) throw new Error('有效时长必须为 1–8760 小时');
        const result = await api('/api/platform/user-invitations', { method: 'POST', body: JSON.stringify({ role_label, policy: {}, expires_at: new Date(Date.now() + hours * 3600 * 1000).toISOString() }) });
        await ElMessageBox.alert(`邀请令牌：${result.token}\n识别码：${result.code}\n\n请在 Infinite AI Chat 注册页填写这两项。识别码只在此处显示，请安全发送。`, '用户邀请已创建', { confirmButtonText: '已保存' });
        await loadPlatform({ silent: true });
      } catch (error) { if (error !== 'cancel' && error !== 'close') message(error.message || '创建失败', 'error'); }
    }
    async function revokePlatformInvitation(item) {
      try { await api(`/api/platform/user-invitations/${item.id}/revoke`, { method: 'POST', body: '{}' }); message('邀请已撤销，无法继续注册'); await loadPlatform({ silent: true }); }
      catch (error) { message(error.message || '撤销失败', 'error'); }
    }
    async function deletePlatformInvitation(item) {
      try { await ElMessageBox.confirm('删除该邀请记录？已领取或已撤销的邀请不会再被使用。', '删除邀请记录', { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' }); await api(`/api/platform/user-invitations/${item.id}`, { method: 'DELETE' }); message('邀请记录已删除'); await loadPlatform({ silent: true }); }
      catch (error) { if (error !== 'cancel' && error !== 'close') message(error.message || '删除失败', 'error'); }
    }
    async function togglePlatformUser(item) {
      const status = item.status === 'active' ? 'suspended' : 'active';
      try { await api(`/api/platform/users/${item.id}`, { method: 'PATCH', body: JSON.stringify({ status }) }); message(status === 'active' ? '用户已启用' : '用户已停用，网页会话和外部 Key 已立即撤销'); await loadPlatform({ silent: true }); }
      catch (error) { message(error.message || '操作失败', 'error'); }
    }
    async function revokePlatformDevice(item) {
      try {
        await ElMessageBox.confirm(`确定立即撤销设备“${item.device_name}”？该设备的 Agent 会话、本地子 Key 和在途调用会同时失效。`, '撤销 Agent 设备', { type: 'warning', confirmButtonText: '立即撤销', cancelButtonText: '取消' });
        await api(`/api/platform/devices/${item.id}`, { method: 'DELETE' });
        message('设备已撤销，关联 Agent 会话和本地子 Key 已立即失效');
        await loadPlatform({ silent: true });
      } catch (error) {
        if (error !== 'cancel' && error !== 'close') message(error.message || '撤销设备失败', 'error');
      }
    }
    async function creditPlatformWallet(item) {
      try {
        const tokensText = await platformPrompt('手工充值 Token', `${item.display_name || item.user_email} · ${item.product_scope} 钱包增加 Token`, { placeholder: '100000' });
        const tokens = Number(tokensText);
        if (!Number.isSafeInteger(tokens) || tokens <= 0) throw new Error('请输入正整数 Token 数');
        const reason = await platformPrompt('手工充值 Token', '操作原因（必填，写入审计）', { placeholder: '人工充值' });
        await ElMessageBox.confirm(`确认向 ${item.product_scope} 钱包增加 ${formatNumber(tokens)} Token？Chat、Agent 与外部 API 彼此独立。`, '确认充值', { type: 'warning', confirmButtonText: '确认充值', cancelButtonText: '取消' });
        await api(`/api/platform/users/${item.user_id}/wallets/${item.product_scope}/credit`, { method: 'POST', body: JSON.stringify({ tokens, reason }) }); message('Token 已充值并写入不可变账本'); await loadPlatform({ silent: true });
      } catch (error) { if (error !== 'cancel' && error !== 'close') message(error.message || '充值失败', 'error'); }
    }
    async function createPaymentProvider() {
      try {
        const provider_type = await platformPrompt('保存支付配置', '支付类型（例如 stripe、alipay 或 wechat_pay）', { value: 'stripe' });
        const merchant_id = await platformPrompt('保存支付配置', '商户号 / 账号 ID');
        const configurationText = await platformPrompt('保存支付配置', '配置 JSON（仅加密保存，当前不会启用）', { value: '{}' });
        let configuration = {};
        try { configuration = JSON.parse(configurationText || '{}'); } catch { throw new Error('配置必须是 JSON 对象'); }
        if (!configuration || Array.isArray(configuration) || typeof configuration !== 'object') throw new Error('配置必须是 JSON 对象');
        await api('/api/platform/payments/providers', { method: 'POST', body: JSON.stringify({ provider_type, merchant_id, configuration, enabled: false }) });
        message('支付配置已加密保存，真实商户验签/对账完成前保持未启用'); await loadPlatform({ silent: true });
      } catch (error) { if (error !== 'cancel') message(error.message || '已取消保存', 'error'); }
    }
    async function disablePaymentProvider(item) {
      try {
        await api(`/api/platform/payments/providers/${item.id}`, { method: 'PATCH', body: JSON.stringify({ enabled: false }) });
        message('支付配置已保持停用'); await loadPlatform({ silent: true });
      } catch (error) { message(error.message || '支付配置更新失败', 'error'); }
    }

    async function login() {
      if (loginLoading.value) return;
      loginError.value = '';
      const usernameValue = loginForm.username.trim(), passwordValue = loginForm.password;
      if (!usernameValue || !passwordValue || !/^\d{6}$/.test(loginForm.totp_code.trim())) { loginError.value = '请输入管理员账号、密码和 6 位动态验证码'; return; }
      loginLoading.value = true;
      try { const result = await api('/api/login', { method: 'POST', body: JSON.stringify({ username: usernameValue, password: passwordValue, totp_code: loginForm.totp_code.trim() }) }); csrf.value = result.csrf_token; username.value = usernameValue; authenticated.value = true; loginForm.password = ''; loginForm.totp_code = ''; await loadAll(); }
      catch (error) { loginError.value = error.message; }
      finally { loginLoading.value = false; }
    }

    async function startSetup() {
	  if (setupLoading.value) return;
      setupError.value = '';
      if (!setupForm.initialization_password || setupForm.username.trim().length < 3) return setupError.value = '请填写初始化口令和新管理员账号';
      if (!validAdminPassword(setupForm.password) || setupForm.password !== setupForm.confirm) return setupError.value = '新密码必须为 12–256 字节，且两次输入必须一致';
      setupLoading.value = true;
      try {
        const result = await api('/api/setup/start', { method: 'POST', body: JSON.stringify({ initialization_password: setupForm.initialization_password, username: setupForm.username.trim(), password: setupForm.password }) });
        Object.assign(setupResult, result); setupStage.value = 1; setupForm.initialization_password = ''; setupForm.password = ''; setupForm.confirm = '';
      } catch (error) { setupError.value = error.message; }
      finally { setupLoading.value = false; }
    }

    async function completeSetup() {
	  if (setupLoading.value) return;
      setupError.value = '';
      if (!/^\d{6}$/.test(setupForm.totp_code.trim())) return setupError.value = '请输入 Microsoft Authenticator 中当前的 6 位验证码';
      setupLoading.value = true;
      try {
        const result = await api('/api/setup/complete', { method: 'POST', body: JSON.stringify({ setup_token: setupResult.setup_token, code: setupForm.totp_code.trim() }) });
        setupStage.value = 2; setupRequired.value = false; authenticated.value = true; csrf.value = result.csrf_token; username.value = result.username; resetSetupSecrets(); await loadAll();
      } catch (error) { setupError.value = error.message; }
      finally { setupLoading.value = false; }
    }
    async function logout() {
	  if (logoutLoading.value) return;
	  logoutLoading.value = true;
      try {
        await api('/api/logout', { method: 'POST', body: '{}' });
        expireAuthenticatedState();
      } catch (error) {
        if (authenticated.value) message(`服务端注销未完成：${error.message || '请重试'}`, 'error');
	  } finally { logoutLoading.value = false; }
    }
    function selectTab(value) {
      if (typeof value !== 'string' || !validTabs.has(value)) return;
      tab.value = value;
      if (window.location.hash !== `#/${value}`) window.location.hash = `/${value}`;
	  if (value === 'platform') void loadPlatform();
    }
    function openAccountDialog() { accountDialogVisible.value = true; }
    function resetAccountDialog() { oauth.sessionId = ''; oauth.url = ''; oauth.callbackURL = ''; oauth.loading = false; oauth.completing = false; oauthForm.name = ''; manualAccount.name = ''; manualAccount.auth = ''; accountMethod.value = 'oauth'; }

    async function startOpenAIOAuth() {
	  if (oauth.loading) return;
      if (!oauthForm.name.trim()) return message('请先填写账号备注', 'warning');
      oauth.loading = true;
      try { const result = await api('/api/accounts/oauth/openai/start', { method: 'POST', body: '{}' }); oauth.sessionId = result.session_id; oauth.url = result.auth_url; oauth.callbackURL = ''; message('授权链接已生成'); }
      catch (error) { message(error.message, 'error'); }
      finally { oauth.loading = false; }
    }
    async function completeOpenAIOAuth() {
	  if (oauth.completing) return;
      if (!oauth.callbackURL.trim()) return message('请粘贴完整 localhost 回跳链接', 'warning');
      oauth.completing = true;
      try { await api('/api/accounts/oauth/openai/complete', { method: 'POST', body: JSON.stringify({ session_id: oauth.sessionId, callback_url: oauth.callbackURL.trim(), name: oauthForm.name.trim() }) }); message('ChatGPT OAuth 账号已添加，正在同步额度'); accountDialogVisible.value = false; await loadAll(); }
      catch (error) { message(error.message, 'error'); }
      finally { oauth.completing = false; }
    }
    async function createManualAccount() {
      if (manualAccountLoading.value) return;
      if (!manualAccount.name.trim() || !manualAccount.auth.trim()) return message('请填写账号备注并粘贴 auth.json', 'warning');
      let auth; try { auth = JSON.parse(manualAccount.auth); } catch { return message('auth.json 格式不正确', 'error'); }
      manualAccountLoading.value = true;
      try { await api('/api/accounts', { method: 'POST', body: JSON.stringify({ name: manualAccount.name.trim(), auth }) }); message('账号已添加，正在同步额度'); accountDialogVisible.value = false; await loadAll(); }
      catch (error) { message(error.message, 'error'); }
      finally { manualAccountLoading.value = false; }
    }
    async function refreshQuota(account) {
      if (accountRowLoading[String(account.id)]) return;
      setAccountRowLoading(account, 'refresh');
      try {
        const snapshot = await api(`/api/accounts/${account.id}/quota/refresh`, { method: 'POST', body: '{}' });
        Object.assign(account, snapshot || {});
        account.quota_updated_at = Number(snapshot?.fetched_at) || account.quota_updated_at || 0;
        account.quota_error = '';
        message('额度已同步');
        void loadAll({ silent: true });
      } catch (error) {
        message(error.message, 'error');
        // The upstream refresh can finish after the browser loses its response.
        // Re-read the stored snapshot rather than leaving an obsolete meter.
        if (authenticated.value) await loadAll({ silent: true });
      }
      finally { setAccountRowLoading(account); }
    }
    async function resetQuota(account) {
      if (accountRowLoading[String(account.id)]) return;
      const expiry = account.reset_credit_times?.[0] ? `\n当前最近到期：${account.reset_credit_times[0]}` : '';
	  setAccountRowLoading(account, 'reset');
	  try {
		await ElMessageBox.confirm(`确定消耗 ${account.name} 的 1 次 ChatGPT 重置次数？${expiry}`, '确认使用重置', { type: 'warning', confirmButtonText: '确定', cancelButtonText: '取消' });
        await api(`/api/accounts/${account.id}/quota/reset`, { method: 'POST', body: '{}' });
        message('已向 ChatGPT 上游提交额度重置');
        await loadAll({ silent: true });
      } catch (error) {
        if (error !== 'cancel' && error !== 'close') {
          message(error.message || '操作失败', 'error');
          if (authenticated.value) await loadAll({ silent: true });
        }
      }
      finally { setAccountRowLoading(account); }
    }
    async function toggleAccount(account) {
      if (accountRowLoading[String(account.id)]) return;
      setAccountRowLoading(account, 'toggle');
      try {
        const result = await api(`/api/accounts/${account.id}`, { method: 'PATCH', body: JSON.stringify({ active: !account.active }) });
        account.active = !account.active;
        const cancelled = Number(result?.cancelled_requests) || 0;
        message(account.active ? '账号已启用' : (cancelled ? `账号已停用，${cancelled} 个在途请求已终止` : '账号已停用'));
        void loadAll({ silent: true });
      } catch (error) {
        message(error.message, 'error');
        // The active flag is committed before the server waits for in-flight
        // requests to drain, so a timeout response can still mean success.
        if (authenticated.value) await loadAll({ silent: true });
      }
      finally { setAccountRowLoading(account); }
    }
    async function deleteAccount(account) {
      if (accountRowLoading[String(account.id)]) return;
      setAccountRowLoading(account, 'delete');
      try {
        await ElMessageBox.confirm(`确定永久删除 ChatGPT 账号“${account.name}”？\n删除后该授权不能继续承载任何上游请求，操作不可恢复。`, '删除 ChatGPT 账号', { type: 'error', confirmButtonText: '永久删除', cancelButtonText: '取消' });
        const result = await api(`/api/accounts/${account.id}`, { method: 'DELETE' });
        accounts.value = accounts.value.filter(item => item.id !== account.id);
        removeAccountModelSnapshot(account);
        if (account.active && Number(dashboard.value.accounts) > 0) dashboard.value.accounts = Number(dashboard.value.accounts) - 1;
        const cancelled = Number(result?.cancelled_requests) || 0;
        message(cancelled ? `账号已删除，${cancelled} 个在途请求已终止` : 'ChatGPT 账号已永久删除');
        void loadAll({ silent: true });
      } catch (error) {
        if (error !== 'cancel' && error !== 'close') {
          message(error.message || '删除账号失败', 'error');
          // A drain-timeout or lost response can happen after the credential
          // transaction committed. Re-read instead of leaving a deleted
          // account visible as if it could still accept traffic.
          if (authenticated.value) await loadAll({ silent: true });
        }
      } finally { setAccountRowLoading(account); }
    }
    function openModelDialog() {
      if (!dataState.models.loaded) return message(dataState.models.error || '模型目录尚未读取完成，请先获取模型列表', 'warning');
      modelDialogVisible.value = true;
    }
    async function refreshAccountModels() {
      if (modelRefreshing.value) return;
      modelRefreshing.value = true;
      try {
        let result = await api('/api/accounts/models/refresh', { method: 'POST', body: '{}', timeoutMS: 120000 });
        if (!isAccountModelsPayload(result)) result = await apiWithTimeout('/api/accounts/models', {}, 35000);
        applyAccountModels(result);
        dataState.models.loaded = true;
        dataState.models.error = '';
        modelDialogVisible.value = true;
        const failures = modelAccountErrorCount.value;
        message(failures ? `模型目录已更新，共 ${modelCatalogCount.value} 个模型；${failures} 个账号同步失败` : `模型目录已更新，共 ${modelCatalogCount.value} 个模型`, failures ? 'warning' : 'success');
      } catch (error) {
        dataState.models.error = error.message || '模型目录刷新失败';
        message(dataState.models.error, 'error');
      } finally { modelRefreshing.value = false; }
    }

    async function saveDesktopUserKey(user) {
      const id = String(user.id);
      if (desktopUserRowLoading[id]) return;
      const apiKeyID = Number(desktopUserKeyDrafts[id]) || 0;
      desktopUserRowLoading[id] = 'key';
      try {
        await api(`/api/desktop/users/${user.id}`, { method: 'PATCH', body: JSON.stringify({ status: user.status, api_key_id: apiKeyID }) });
        user.api_key_id = apiKeyID;
        user.key_role = desktopKeyOptions.value.find(item => Number(item.id) === apiKeyID)?.role || '';
        desktopUserKeyDirty[id] = false;
        message(apiKeyID ? '桌面用户已绑定该 Key，下一次请求立即使用新归属' : '已取消该用户的 Key 授权，后续调用立即停止');
        void loadAll({ silent: true });
      } catch (error) {
        message(error.message || '保存用户授权失败', 'error');
        if (authenticated.value) await loadAll({ silent: true });
      } finally { delete desktopUserRowLoading[id]; }
    }

    async function toggleDesktopUser(user) {
      const id = String(user.id);
      if (desktopUserRowLoading[id]) return;
      const disabling = user.status === 'active';
      desktopUserRowLoading[id] = 'status';
      try {
        if (disabling) await ElMessageBox.confirm(`停用 ${user.display_name || user.email} 后，网页与全部桌面会话会立即失效。`, '停用 Infinite AI 用户', { type: 'warning', confirmButtonText: '立即停用', cancelButtonText: '取消' });
        const status = disabling ? 'disabled' : 'active';
        await api(`/api/desktop/users/${user.id}`, { method: 'PATCH', body: JSON.stringify({ status, api_key_id: Number(user.api_key_id) || 0 }) });
        user.status = status;
        message(disabling ? '用户已停用，全部登录会话已立即撤销' : '用户已启用');
        void loadAll({ silent: true });
      } catch (error) {
        if (error !== 'cancel' && error !== 'close') message(error.message || '更新用户状态失败', 'error');
      } finally { delete desktopUserRowLoading[id]; }
    }

    async function revokeDesktopDevice(device) {
      const id = String(device.id);
      if (desktopDeviceRowLoading[id] || device.status !== 'active') return;
      desktopDeviceRowLoading[id] = true;
      try {
        await ElMessageBox.confirm(`确定让设备“${device.name}”立即退出？该设备的全部桌面会话会同时失效。`, '撤销桌面设备', { type: 'warning', confirmButtonText: '立即退出', cancelButtonText: '取消' });
        await api(`/api/desktop/devices/${device.id}`, { method: 'DELETE' });
        device.status = 'revoked';
        message('设备已撤销，软件将在长轮询检测后立即返回登录页');
        void loadAll({ silent: true });
      } catch (error) {
        if (error !== 'cancel' && error !== 'close') message(error.message || '撤销设备失败', 'error');
      } finally { delete desktopDeviceRowLoading[id]; }
    }

    async function saveDesktopPolicy() {
      if (desktopPolicySaving.value) return;
      const provider = desktopPolicyForm.provider_name.trim();
      const model = desktopPolicyForm.default_model.trim();
      if (!provider || !model) return message('供应商名称和默认模型不能为空', 'warning');
      desktopPolicySaving.value = true;
      try {
        const payload = {
          ...desktopPolicyForm,
		  public_api_enabled: desktopPolicyForm.external_api_mode === 'authenticated_public',
		  official_desktop_only: desktopPolicyForm.external_api_mode === 'official_client_only',
          provider_name: provider,
          default_model: model,
          allowed_models: [...new Set((desktopPolicyForm.allowed_models || []).map(item => String(item).trim()).filter(Boolean))]
        };
        const result = await api('/api/desktop/policy', { method: 'PUT', body: JSON.stringify(payload) });
        applyDesktopPolicy(result);
        message('Infinite AI 桌面策略已保存；模型与提示词在客户端下次载入时生效，访问开关立即生效');
      } catch (error) { message(error.message || '保存桌面策略失败', 'error'); }
      finally { desktopPolicySaving.value = false; }
    }

    function openInviteDialog() { inviteResult.value = null; inviteDialogVisible.value = true; }
    function resetInviteDialog() { inviteResult.value = null; Object.assign(inviteForm, { role: '', recognition_code: '', quota_requests: 0, expires_hours: 168, binding_mode: 'ip' }); }
    async function createInvitation() { if (inviteLoading.value) return; if (!inviteForm.role.trim()) return message('请填写角色备注', 'warning'); inviteLoading.value = true; try { inviteResult.value = await api('/api/invitations', { method: 'POST', body: JSON.stringify(inviteForm) }); Object.assign(inviteForm, { role: '', recognition_code: '', quota_requests: 0, expires_hours: 168, binding_mode: 'ip' }); message('邀请已生成，请保存链接和识别码'); await loadAll(); } catch (error) { message(error.message, 'error'); } finally { inviteLoading.value = false; } }
    async function revokeInvitation(invite) {
      if (inviteRowLoading[String(invite.id)]) return;
	  setInviteRowLoading(invite, 'revoke');
	  try {
		await ElMessageBox.confirm(`确定撤销“${invite.role}”的邀请？`, '撤销邀请', { type: 'warning', confirmButtonText: '撤销', cancelButtonText: '取消' });
        await api(`/api/invitations/${invite.id}`, { method: 'DELETE' });
        invite.status = 'revoked';
        invite.invite_url = '';
        message('邀请已撤销，原链接立即失效');
        void loadAll({ silent: true });
      } catch (error) {
        if (error !== 'cancel' && error !== 'close') {
          message(error.message || '操作失败', 'error');
          if (authenticated.value) await loadAll({ silent: true });
        }
      } finally { setInviteRowLoading(invite); }
    }
    async function deleteInvitation(invite) {
      if (inviteRowLoading[String(invite.id)]) return;
	  setInviteRowLoading(invite, 'delete');
	  try {
		await ElMessageBox.confirm(`确定永久删除“${invite.role}”的邀请记录？\n注意：这是删除邀请元数据，不会停用或删除已经领取的 API Key；如需停止调用，请进入 API 密钥页操作。`, '删除邀请记录', { type: 'warning', confirmButtonText: '删除记录', cancelButtonText: '取消' });
        await api(`/api/invitations/${invite.id}/permanent`, { method: 'DELETE' });
        invites.value = invites.value.filter(item => item.id !== invite.id);
        message('邀请记录已删除；已领取 Key 的状态未改变');
        void loadAll({ silent: true });
      } catch (error) {
        if (error !== 'cancel' && error !== 'close') {
          message(error.message || '操作失败', 'error');
          if (authenticated.value) await loadAll({ silent: true });
        }
      } finally { setInviteRowLoading(invite); }
    }
    function openKeyFromInvite(invite) { selectTab('keys'); message(`已切换到 API 密钥页，请管理 Key #${invite.api_key_id}`, 'info'); }
    async function copyText(value) {
      let copied = false;
      try {
        await navigator.clipboard.writeText(value);
        copied = true;
      } catch {
        const area = document.createElement('textarea');
        area.value = value;
        area.setAttribute('readonly', '');
        area.style.position = 'fixed';
        area.style.opacity = '0';
        document.body.append(area);
        area.select();
        try { copied = document.execCommand('copy') === true; } catch { copied = false; }
        area.remove();
      }
      if (!copied) {
        message('复制失败，请检查浏览器剪贴板权限', 'error');
        return false;
      }
      message('已复制到剪贴板');
      return true;
    }
    async function copyKey(key) {
      if (keyRowLoading[String(key.id)]) return;
      setKeyRowLoading(key, 'copy');
      try { const result = await api(`/api/keys/${key.id}/copy`, { method: 'POST', body: '{}' }); await copyText(result.key); }
      catch (error) { message(error.message, 'error'); }
      finally { setKeyRowLoading(key); }
    }
    async function saveKey(key) {
      if (keyRowLoading[String(key.id)]) return;
      const id = String(key.id);
      const quota = Number(keyQuotaDrafts[id]);
      if (!Number.isSafeInteger(quota) || quota < 0) return message('请求额度必须是大于或等于 0 的整数', 'warning');
      setKeyRowLoading(key, 'save');
      try {
        await api(`/api/keys/${key.id}`, { method: 'PATCH', body: JSON.stringify({ status: key.status, quota_requests: quota }) });
        key.quota_requests = quota;
        keyQuotaDirty[id] = false;
        message('Key 额度已保存并立即生效');
        void loadAll({ silent: true });
      } catch (error) {
        message(error.message, 'error');
        if (authenticated.value) await loadAll({ silent: true });
      }
      finally { setKeyRowLoading(key); }
    }
    async function toggleKey(key) {
      if (keyRowLoading[String(key.id)]) return;
      const disabling = key.status === 'active';
      const nextStatus = disabling ? 'disabled' : 'active';
      setKeyRowLoading(key, 'toggle');
      try {
        // Only submit the last saved quota. A quota draft must never be
        // persisted as a side effect of enabling or disabling a key.
        const result = await api(`/api/keys/${key.id}`, { method: 'PATCH', body: JSON.stringify({ status: nextStatus, quota_requests: Number(key.quota_requests) || 0 }) });
        key.status = nextStatus;
        invites.value.forEach(invite => { if (invite.api_key_id === key.id) invite.api_key_status = nextStatus; });
        const cancelled = Number(result.cancelled_requests) || 0;
        message(disabling ? (cancelled ? `Key 已停用：已等待 ${cancelled} 个在途请求退出` : 'Key 已停用：当前没有在途请求') : 'Key 已启用');
        void loadAll({ silent: true });
      } catch (error) {
        message(error.message, 'error');
        // A timeout may be the drain acknowledgement rather than a failed
        // state transition. Re-read so a disabled key is never shown active.
        if (authenticated.value) await loadAll({ silent: true });
      }
      finally { setKeyRowLoading(key); }
    }
    async function deleteKey(key) {
      if (keyRowLoading[String(key.id)]) return;
	  setKeyRowLoading(key, 'delete');
	  try {
		await ElMessageBox.confirm(`确定永久删除 ${key.role} 的 Key #${key.id}？\n删除后立即失效，密文、IP 白名单和会话粘连会被销毁；历史使用记录仍保留用于审计。`, '永久删除 API Key', { type: 'error', confirmButtonText: '永久删除', cancelButtonText: '取消' });
        const result = await api(`/api/keys/${key.id}`, { method: 'DELETE', body: '{}' });
        keys.value = keys.value.filter(item => item.id !== key.id);
        delete keyQuotaDrafts[String(key.id)];
        delete keyQuotaDirty[String(key.id)];
        invites.value.forEach(invite => { if (invite.api_key_id === key.id) invite.api_key_status = 'deleted'; });
        const cancelled = Number(result.cancelled_requests) || 0;
        message(cancelled ? `Key 已删除：已等待 ${cancelled} 个在途请求退出，密文与授权已销毁` : 'Key 已删除：密文与授权已销毁，当前无在途请求');
        void loadAll({ silent: true });
      } catch (error) {
        if (error !== 'cancel' && error !== 'close') {
          message(error.message || '删除失败', 'error');
          if (authenticated.value) await loadAll({ silent: true });
        }
      } finally { setKeyRowLoading(key); }
    }
    async function addKeyIP(key) {
      if (keyRowLoading[String(key.id)]) return;
	  setKeyRowLoading(key, 'ip');
      try {
		const first = await ElMessageBox.prompt('输入要授权的公网 IPv4 或 IPv6', `为 ${key.role} 添加 IP`, { inputPlaceholder: '例如：203.0.113.10', confirmButtonText: '下一步', cancelButtonText: '取消' });
		const second = await ElMessageBox.prompt('输入该 IP 下机器的设备备注', '设备备注', { inputPlaceholder: '例如：我的 MacBook', confirmButtonText: '添加', cancelButtonText: '取消' });
        await api(`/api/keys/${key.id}/ips`, { method: 'POST', body: JSON.stringify({ ip: first.value, device_note: second.value }) });
        message('IP 已加入白名单并立即生效');
        await loadAll({ silent: true });
      } catch (error) {
        if (error !== 'cancel' && error !== 'close') {
          message(error.message || '操作失败', 'error');
          if (authenticated.value) await loadAll({ silent: true });
        }
      } finally { setKeyRowLoading(key); }
    }
    async function deleteKeyIP(key, ip) {
      if (keyRowLoading[String(key.id)]) return;
	  setKeyRowLoading(key, 'ip');
      try {
        await ElMessageBox.confirm(`确定删除 ${ip.ip} 的授权？`, '删除 IP 白名单', { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' });
        const result = await api(`/api/keys/${key.id}/ips/${ip.id}`, { method: 'DELETE' });
        key.allowed_ips = (key.allowed_ips || []).filter(item => item.id !== ip.id);
        const cancelled = Number(result.cancelled_requests) || 0;
        message(cancelled ? `IP 授权已删除，已等待 ${cancelled} 个在途请求退出` : 'IP 授权已删除，当前无在途请求');
        void loadAll({ silent: true });
      } catch (error) {
        if (error !== 'cancel' && error !== 'close') {
          message(error.message || '操作失败', 'error');
          if (authenticated.value) await loadAll({ silent: true });
        }
      } finally { setKeyRowLoading(key); }
    }
    async function unban(item) {
      if (banRowLoading[item.ip]) return;
	  setBanRowLoading(item, true);
	  try {
		const result = await api(`/api/system/bans/${base64url(item.ip)}/unban`, { method: 'POST', body: '{}' });
		const removed = new Set(result.unbanned_ips || [item.ip]);
		bans.value = bans.value.filter(entry => !removed.has(entry.ip));
		dashboard.value.bans = bans.value.length;
		message(removed.size > 1 ? `已解除 ${removed.size} 个同设备 IPv4 / IPv6 封禁${result.cache_degraded ? '，但撤销缓存同步降级' : ''}` : `IP 已解除封禁${result.cache_degraded ? '，但撤销缓存同步降级' : ''}`, result.cache_degraded ? 'warning' : 'success');
		await refreshBanListAfterMutation();
      } catch (error) {
        message(error.message, 'error');
        if (authenticated.value) await refreshBanListAfterMutation();
      }
      finally { setBanRowLoading(item, false); }
    }

    async function saveProtection(enabled) {
	  if (securitySaving.value) return;
	  if (!dataState.security.loaded || dataState.security.error) return message('安全状态未成功读取或最近刷新失败，不能保存或覆盖服务端配置', 'error');
      if (securityForm.protection_enabled === true && securityForm.nginx_protection === true && !security.value.nginx?.available) {
        securityForm.nginx_protection = false;
        message('本机未检测到可读的 Nginx 配置；已开启其他防护，但不会开启无效的 Nginx 监控', 'warning');
      }
      securitySaving.value = true;
      try { security.value = await api('/api/system/security', { method: 'PUT', body: JSON.stringify(securityForm) }); Object.assign(securityForm, security.value.config || {}); message(securityForm.protection_enabled ? '安全保护已开启' : '安全策略已保存'); }
      catch (error) { message(error.message, 'error'); await loadAll(); }
      finally { securitySaving.value = false; }
    }
    async function confirmNginxBaseline() {
	  if (securitySaving.value) return;
	  if (!dataState.security.loaded || dataState.security.error) return message('安全状态未成功读取或最近刷新失败，不能更新 Nginx 基线', 'error');
	  securitySaving.value = true;
	  try { await ElMessageBox.confirm('确认当前 Nginx 文件内容、权限与符号链接为可信配置？之后发生任何变化都会触发警告。', '更新 Nginx 基线', { type: 'warning', confirmButtonText: '确认基线', cancelButtonText: '取消' }); security.value = await api('/api/system/security/nginx/baseline', { method: 'POST', body: '{}' }); message('Nginx 配置基线已更新'); }
	  catch (error) { if (error !== 'cancel' && error !== 'close') message(error.message || '操作失败', 'error'); }
	  finally { securitySaving.value = false; }
    }
    async function banIP() {
	  if (banSaving.value) return;
      if (!banForm.ip.trim()) return message('请输入要封禁的 IP', 'warning');
      banSaving.value = true;
	  try {
		const submitted = { ...banForm };
		const result = await api('/api/system/bans', { method: 'POST', body: JSON.stringify(submitted) });
		const now = Math.floor(Date.now() / 1000);
		for (const ip of result.banned_ips || [submitted.ip]) {
		  const next = { ip, reason: submitted.reason || '管理员手动封禁', scope: 'all', attempts: 0, created_at: now, expires_at: submitted.permanent ? 0 : now + submitted.hours * 3600 };
		  const index = bans.value.findIndex(item => item.ip === ip);
		  if (index >= 0) bans.value[index] = next; else bans.value.unshift(next);
		}
		dashboard.value.bans = bans.value.length;
		const cancelled = Number(result.cancelled_requests) || 0;
		message(`${submitted.permanent ? 'IP 已永久封禁' : 'IP 已临时封禁'}${cancelled ? `，已等待 ${cancelled} 个在途请求退出` : ''}${result.cache_degraded ? '；但封禁缓存全量同步降级' : ''}`, result.cache_degraded ? 'warning' : 'success');
		banDialogVisible.value = false;
		Object.assign(banForm, { ip: '', reason: '', hours: 24, permanent: false });
		await refreshBanListAfterMutation();
	  }
	  catch (error) {
		message(error.message, 'error');
		// ban_drain_timeout is returned after the blacklist transaction has
		// committed, so an error response must still refresh the visible list.
		if (authenticated.value) await refreshBanListAfterMutation();
	  }
      finally { banSaving.value = false; }
    }
    async function changePassword() {
	  if (passwordSaving.value) return;
      if (!passwordForm.current_password || !validAdminPassword(passwordForm.new_password) || passwordForm.new_password !== passwordForm.confirm || !/^\d{6}$/.test(passwordForm.totp_code.trim())) return message('请完整填写；新密码必须为 12–256 字节且两次一致，动态验证码为 6 位', 'warning');
      passwordSaving.value = true;
      try { await api('/api/system/password', { method: 'POST', body: JSON.stringify({ current_password: passwordForm.current_password, new_password: passwordForm.new_password, totp_code: passwordForm.totp_code.trim() }) }); expireAuthenticatedState(); message('密码已修改，所有后台会话已注销，请重新登录'); }
      catch (error) { message(error.message, 'error'); }
      finally { passwordSaving.value = false; }
    }

    function openBackupExportDialog() {
      resetBackupExportDialog();
      backupExportDialogVisible.value = true;
    }
    function resetBackupExportDialog() { Object.assign(backupExportForm, { passphrase: '', confirm: '' }); }
    function openBackupImportDialog() {
      resetBackupImportDialog();
      backupImportDialogVisible.value = true;
    }
    function resetBackupImportDialog() {
      backupImportForm.passphrase = '';
      backupImportFile.value = null;
      backupImportFiles.value = [];
    }
    function backupFileChanged(uploadFile, uploadFiles) {
      backupImportFile.value = uploadFile?.raw || null;
      backupImportFiles.value = Array.isArray(uploadFiles) ? uploadFiles.slice(-1) : [];
    }
    function backupFileRemoved() {
      backupImportFile.value = null;
      backupImportFiles.value = [];
    }
    function backupFileExceeded() { message('每次只能导入一个备份文件，请先移除当前文件', 'warning'); }
    function safeBackupFilename(headerValue) {
      const value = String(headerValue || '');
      let filename = '';
      const encoded = value.match(/filename\*=UTF-8''([^;]+)/i);
      if (encoded) {
        try { filename = decodeURIComponent(encoded[1].trim()); } catch { filename = encoded[1].trim(); }
      }
      if (!filename) {
        const plain = value.match(/filename="?([^";]+)"?/i);
        if (plain) filename = plain[1].trim();
      }
      filename = filename.replace(/[\\/:*?"<>|\u0000-\u001f]/g, '_').slice(0, 180);
      if (filename) return filename;
      return `friendgate-backup-${new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)}.fgbackup`;
    }
    function triggerBlobDownload(blob, filename) {
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      link.rel = 'noopener';
      document.body.append(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
    async function exportBackup() {
      if (backupExporting.value) return;
      if (!validBackupPassphrase(backupExportForm.passphrase)) return message('备份密码需要 12–4096 字节', 'warning');
      if (backupExportForm.passphrase !== backupExportForm.confirm) return message('两次输入的备份密码不一致', 'warning');
      backupExporting.value = true;
      try {
        const response = await rawAPI('/api/system/backup/export', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ passphrase: backupExportForm.passphrase }) });
        const blob = await response.blob();
        if (!blob.size) throw new Error('服务器返回了空备份文件');
        const filename = safeBackupFilename(response.headers.get('Content-Disposition') || response.headers.get('X-Backup-Filename'));
        triggerBlobDownload(blob, filename);
        backupExportDialogVisible.value = false;
        resetBackupExportDialog();
        message(`全部数据已加密导出：${filename}`);
      } catch (error) { message(error.message || '导出备份失败', 'error'); }
      finally { backupExporting.value = false; }
    }
    function backupImportSummary(result) {
      const data = result && typeof result === 'object' ? result : {};
      const counts = data.counts && typeof data.counts === 'object' ? data.counts : (data.imported && typeof data.imported === 'object' ? data.imported : data);
      const fields = [
        { keys: ['accounts'], label: 'ChatGPT 账号' },
        { keys: ['api_keys', 'keys'], label: 'API 密钥' },
        { keys: ['invitations'], label: '邀请' },
        { keys: ['allowed_ips'], label: 'IP 授权' },
        { keys: ['bans'], label: 'IP 封禁' },
        { keys: ['usage'], label: '使用记录' },
        { keys: ['logs'], label: '日志' },
        { keys: ['settings'], label: '系统设置' }
      ];
      const details = fields.flatMap(field => {
        const key = field.keys.find(candidate => Number.isFinite(Number(counts[candidate])));
        return key ? [`${field.label} ${formatNumber(counts[key])} 条`] : [];
      });
      if (Number.isFinite(Number(data.tables))) details.unshift(`数据表 ${formatNumber(data.tables)} 个`);
      if (Number.isFinite(Number(data.rows))) details.push(`数据行 ${formatNumber(data.rows)} 条`);
      if (Number.isFinite(Number(data.cancelled_requests))) details.push(`终止在途请求 ${formatNumber(data.cancelled_requests)} 个`);
      if (typeof data.cache_degraded === 'boolean') details.push(data.cache_degraded ? '请求撤销缓存同步：降级' : '请求撤销缓存同步：正常');
      if (typeof data.requires_relogin === 'boolean') details.push(data.requires_relogin ? '管理员会话：已注销，需重新登录' : '管理员会话：保持');
      const title = String(data.message || (data.requires_relogin ? '备份已恢复，当前后台会话已安全注销' : '备份校验通过，数据已导入'));
      return { text: [title, details.join(' · ')].filter(Boolean).join('\n'), type: data.cache_degraded === true ? 'warning' : 'success' };
    }
    async function importBackup() {
      if (backupImporting.value) return;
      if (!backupImportFile.value) return message('请先选择备份文件', 'warning');
      if (!validBackupPassphrase(backupImportForm.passphrase)) return message('备份解密密码需要 12–4096 字节', 'warning');
      try {
        await ElMessageBox.confirm('导入会按服务器规则恢复备份中的全部数据，可能覆盖当前同标识记录。请确认已保存现有备份并核对文件来源。', '确认导入加密备份', { type: 'warning', confirmButtonText: '确认导入', cancelButtonText: '取消' });
      } catch (error) {
        if (error !== 'cancel' && error !== 'close') message(error.message || '无法确认导入', 'error');
        return;
      }
      backupImporting.value = true;
      try {
        const form = new FormData();
        form.append('backup', backupImportFile.value, backupImportFile.value.name || 'friendgate-backup.fgbackup');
        form.append('passphrase', backupImportForm.passphrase);
        const response = await rawAPI('/api/system/backup/import', { method: 'POST', body: form }, 180000);
        let result = {};
        try { result = await response.json(); } catch {}
        const summary = backupImportSummary(result);
        backupImportDialogVisible.value = false;
        resetBackupImportDialog();
        message(result.cache_degraded === true ? '备份已导入，但请求撤销缓存同步降级' : '备份导入完成', summary.type);
        await ElMessageBox.alert(summary.text, '导入结果', {
          type: summary.type,
          confirmButtonText: '知道了，重新登录',
          showClose: false,
          closeOnClickModal: false,
          closeOnPressEscape: false
        }).catch(() => {});
        expireAuthenticatedState();
        loginError.value = result.requires_relogin === false
          ? '备份已恢复；为安全起见，请重新登录后继续操作'
          : '备份已恢复，请使用恢复后的管理员账号、密码和 2FA 重新登录';
      } catch (error) { message(error.message || '导入备份失败', 'error'); }
      finally { backupImporting.value = false; }
    }

    const applyRoute = () => {
      const route = window.location.hash.replace(/^#\/?/, '');
      if (validTabs.has(route)) tab.value = route;
    };
    const handleVisibilityChange = () => {
      nowSeconds.value = Math.floor(Date.now() / 1000);
      if (!document.hidden && authenticated.value) {
		if (tab.value === 'dashboard') void refreshDashboardLive({ force: true });
		else if (tab.value === 'platform') void loadPlatform({ silent: true });
		else void loadAll({ silent: true });
      }
    };
    watch(tab, value => {
      if (value === 'dashboard' && authenticated.value && !document.hidden) void refreshDashboardLive({ force: true });
	  if (value === 'platform' && authenticated.value) void loadPlatform();
    });
    onMounted(async () => {
      applyRoute();
      window.addEventListener('hashchange', applyRoute);
      document.addEventListener('visibilitychange', handleVisibilityChange);
      clockTimer = window.setInterval(() => { nowSeconds.value = Math.floor(Date.now() / 1000); }, 1000);
      dashboardLiveTimer = window.setInterval(() => { void refreshDashboardLive(); }, 5000);
      pollTimer = window.setInterval(() => { if (authenticated.value && !document.hidden && tab.value !== 'dashboard') { if (tab.value === 'platform') void loadPlatform({ silent: true }); else void loadAll({ silent: true }); } }, 60000);
      try {
        const me = await api('/api/me');
        setupRequired.value = !!me.setup_required;
        if (setupRequired.value || !me.authenticated) return;
        csrf.value = me.csrf_token;
        username.value = me.username;
        authenticated.value = true;
        await loadAll();
      } catch (error) { loginError.value = error.message || '无法读取后台登录状态，请刷新后重试'; }
      finally { bootstrapped.value = true; }
    });
    onBeforeUnmount(() => {
      window.removeEventListener('hashchange', applyRoute);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      if (clockTimer) window.clearInterval(clockTimer);
      if (dashboardLiveTimer) window.clearInterval(dashboardLiveTimer);
      if (pollTimer) window.clearInterval(pollTimer);
    });
    return {
      bootstrapped, authenticated, setupRequired, setupStage, setupLoading, setupError, setupForm, setupResult, startSetup, completeSetup,
      username, tab, systemPanel, loading, lastRefreshAt, refreshErrors, loginLoading, logoutLoading, loginError, loginForm, dashboard,
	  accounts, accountModels, modelCatalogModels, modelCatalogCount, modelAccountErrorCount, modelDialogVisible, modelRefreshing, platform,
	  keys, desktopUsers, desktopDevices, desktopPolicy, desktopPolicyForm, desktopPolicySaving, desktopKeyOptions,
	  desktopUserKeyDrafts, desktopUserKeyDirty, desktopUserRowLoading, desktopDeviceRowLoading,
	  markDesktopUserKeyDirty, saveDesktopUserKey, toggleDesktopUser, revokeDesktopDevice, saveDesktopPolicy,
	  invites, bans, usage, pageMeta, dashboardMetrics, resourceCards, modelRanking, quotaErrorCount, combinedLogs,
	  usagePage, logPage, recordPageSize, pagedUsage, pagedLogs,
      nowSeconds, mobileTabs, accountDialogVisible, accountMethod, oauthForm, oauth, manualAccount, manualAccountLoading,
      keyQuotaDrafts, keyQuotaDirty, keyRowLoading, inviteRowLoading, accountRowLoading, banRowLoading, markKeyQuotaDirty, isKeyQuotaDirty,
      inviteForm, inviteLoading, inviteResult, inviteDialogVisible, openInviteDialog, resetInviteDialog,
	  security, dataState, securityForm, securitySaving, healthColors, runtimeErrorSummary, saveProtection, confirmNginxBaseline,
      banDialogVisible, banSaving, banForm, banIP, passwordForm, passwordSaving, changePassword,
      backupExportDialogVisible, backupImportDialogVisible, backupExporting, backupImporting, backupExportForm, backupImportForm,
      backupImportFile, backupImportFiles, openBackupExportDialog, resetBackupExportDialog, openBackupImportDialog, resetBackupImportDialog,
      backupFileChanged, backupFileRemoved, backupFileExceeded, exportBackup, importBackup,
	  login, logout, selectTab, loadAll, loadPlatform, createPlatformModel, publishPlatformModel, createPlatformProvider, createPlatformRoutePool, createPlatformAPIKey, togglePlatformKey, copyPlatformKey, deletePlatformKey,
	  createPlatformUpstreamAccount, syncPlatformAccountModels, togglePlatformProvider, testPlatformProvider, deletePlatformProvider, togglePlatformUpstreamAccount, deletePlatformUpstreamAccount, addPlatformRoutePoolMember, createPlatformRouteTarget,
	  setPlatformRegistrationMode, updatePlatformPlan, createPlatformUserInvitation, revokePlatformInvitation, deletePlatformInvitation, togglePlatformUser, revokePlatformDevice, creditPlatformWallet, createPaymentProvider, disablePaymentProvider, openAccountDialog, resetAccountDialog,
      startOpenAIOAuth, completeOpenAIOAuth, createManualAccount, refreshQuota, resetQuota, toggleAccount, deleteAccount,
      openModelDialog, refreshAccountModels,
      createInvitation, revokeInvitation, deleteInvitation, openKeyFromInvite, copyText, copyKey, saveKey, toggleKey, deleteKey, addKeyIP,
      deleteKeyIP, unban, when, formatNumber, formatBytes, hasQuota, quotaPercent, quotaText, quotaColor,
      resetText, inviteStatus, inviteStatusLabel, inviteTag, modelRankPercent, nginxStateText
    };
  }
}).use(ElementPlus).mount('#app');
if (bootFallback) bootFallback.hidden = true;
} catch (error) {
  showBootFailure(`前端启动失败：${error?.message || '未知错误'}`);
  console.error(error);
}
