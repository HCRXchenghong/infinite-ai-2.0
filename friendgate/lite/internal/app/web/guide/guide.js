const $ = selector => document.querySelector(selector);
const state = { key: '', device: '', base: '', role: '', model: '', models: [] };
let pageExitSent = false;

function clearGuideClientState() {
  if (pageExitSent) return;
  pageExitSent = true;
  try {
    sessionStorage.removeItem('friendgate_guide_state');
    localStorage.removeItem('friendgate_guide_state');
  } catch {}
  // pagehide is delivered for tab/window close and navigation. sendBeacon is
  // designed to finish a small POST while the document is being discarded.
  try {
    if (navigator.sendBeacon) {
      navigator.sendBeacon('/api/guide/logout', new Blob([], { type: 'text/plain' }));
    }
  } catch {}
}

window.addEventListener('pagehide', clearGuideClientState, { capture: true });

function setMessage(text) {
  const node = $('#gateMessage');
  node.textContent = text || '';
  node.classList.toggle('hidden', !text);
}

async function api(path, options = {}) {
  const response = await fetch(path, { credentials: 'same-origin', ...options });
  let data = {};
  try { data = await response.json(); } catch {}
  if (!response.ok) throw new Error(data?.error?.message || '请求失败');
  return data;
}

function saveState(data) {
  state.key = data.key || '';
  state.device = data.device_token || '';
  state.base = data.base_url || '';
  state.role = data.role || '';
  // A newly authenticated key must not inherit the previous key's model.
  state.model = '';
  state.models = [];
  sessionStorage.setItem('friendgate_guide_state', JSON.stringify(state));
}

function restoreState() {
  try {
    const saved = JSON.parse(sessionStorage.getItem('friendgate_guide_state') || '{}');
    if (saved.key && saved.base) Object.assign(state, saved);
  } catch {}
}

function copyText(value, button) {
  navigator.clipboard?.writeText(value).then(() => {
    const old = button.textContent;
    button.textContent = '已复制';
    setTimeout(() => { button.textContent = old; }, 1200);
  }).catch(() => {
    const area = document.createElement('textarea');
    area.value = value; document.body.appendChild(area); area.select(); document.execCommand('copy'); area.remove();
    button.textContent = '已复制';
    setTimeout(() => { button.textContent = '复制'; }, 1200);
  });
}

function modelID(entry) {
  if (typeof entry === 'string') return entry.trim();
  return String(entry?.id || entry?.slug || '').trim();
}

function uniqueModelIDs(catalog) {
  const entries = Array.isArray(catalog?.models) ? catalog.models : [];
  return [...new Set(entries.map(modelID).filter(id => id && id.length <= 256 && !/[\u0000\r\n]/.test(id)))].sort((a, b) => a.localeCompare(b));
}

function defaultModel(ids) {
  // Prefer the family alias and official Sol slug, then any real catalog ID
  // containing 5.6 (for example gpt-5.6-codex). Never invent an ID when the
  // gateway has a real snapshot available.
  for (const preferred of ['gpt-5.6', 'gpt-5.6-sol', 'gpt-5.6-codex']) {
    if (ids.includes(preferred)) return preferred;
  }
  return ids.find(id => /(^|[-_.])5[.]6([-_.]|$)/i.test(id) || /gpt-5p6/i.test(id)) || ids[0] || '';
}

function tomlString(value) {
  // JSON basic strings use the same escaping needed by TOML basic strings for
  // the values emitted here, while avoiding a broken config if a future model
  // ID or URL contains a quote or backslash.
  return JSON.stringify(String(value ?? ''));
}

function shellQuote(value) {
  return `'${String(value ?? '').replaceAll("'", "'\\''")}'`;
}

function updateGeneratedConfig() {
  const model = state.model || '';
  const hasFullKey = state.key && !state.key.includes('...');
  const usableKey = hasFullKey ? state.key : '请重新验证后填入完整 Key';
  const deviceLine = state.device ? `\nhttp_headers = { "X-FriendGate-Device-Token" = ${tomlString(state.device)} }` : '';
  const modelLine = model ? `model_provider = "friendgate"\nmodel = ${tomlString(model)}` : 'model_provider = "friendgate"\n# 请选择一个已同步的模型后再复制\nmodel = "gpt-5.6"';
  $('#modelValue').textContent = model || '未同步';
  $('#tomlCode').textContent = `${modelLine}\n\n[model_providers.friendgate]\nname = "FriendGate"\nbase_url = ${tomlString(state.base)}\nenv_key = "FRIENDGATE_API_KEY"\nwire_api = "responses"\nsupports_websockets = true${deviceLine}`;
  $('#authCode').textContent = JSON.stringify({ OPENAI_API_KEY: usableKey }, null, 2);
  $('#shellCode').textContent = `mkdir -p ~/.codex\nchmod 700 ~/.codex\nexport FRIENDGATE_API_KEY=${shellQuote(usableKey)}${state.device ? `\nexport FRIENDGATE_DEVICE_TOKEN=${shellQuote(state.device)}` : ''}\ncodex`;
  const tomlCopy = $('#tomlCopy');
  const authCopy = $('#authCopy');
  const shellCopy = $('#shellCopy');
  if (tomlCopy) tomlCopy.disabled = !model;
  if (authCopy) authCopy.disabled = !hasFullKey;
  if (shellCopy) shellCopy.disabled = !hasFullKey;
}

function setupModelPicker(catalog, loadError) {
  const select = $('#modelSelect');
  const status = $('#modelStatus');
  if (!select || !status) return;
  const ids = uniqueModelIDs(catalog);
  state.models = ids;
  select.replaceChildren();
  if (!ids.length) {
    select.disabled = true;
    select.add(new Option('暂无已同步模型', ''));
    state.model = '';
    status.className = 'model-status error';
    status.textContent = loadError || '后台尚未同步真实模型，请管理员先刷新模型列表。';
    updateGeneratedConfig();
    return;
  }
  select.disabled = false;
  for (const id of ids) select.add(new Option(id, id));
  const preferred = state.model && ids.includes(state.model) ? state.model : defaultModel(ids);
  state.model = preferred;
  select.value = preferred;
  const has56 = ids.some(id => /(^|[-_.])5[.]6([-_.]|$)/i.test(id) || /gpt-5p6/i.test(id));
  status.className = has56 ? 'model-status' : 'model-status warning';
  status.textContent = loadError || (has56 ? '默认已选择 5.6；选择后配置会立即更新。' : '当前同步目录没有 5.6，已选择第一个真实可用模型。');
  select.onchange = () => {
    state.model = select.value;
    try { sessionStorage.setItem('friendgate_guide_state', JSON.stringify(state)); } catch {}
    status.className = 'model-status';
    status.textContent = '配置已更新，可直接复制。';
    updateGeneratedConfig();
  };
  updateGeneratedConfig();
}

async function renderGuide() {
  const content = await api('/api/guide/content');
  $('#guideContent').innerHTML = content.html || '';
  // The injected document contains the TOC and article as the two grid
  // children. Keep the loader wrapper transparent so neither section is
  // collapsed into a single narrow column.
  $('#guideContent').style.display = 'contents';
  $('#gate').classList.add('hidden');
  $('#guide').classList.remove('hidden');
  $('#welcome').textContent = `${state.role || '已授权用户'}，以下配置已按本次凭证自动填充。`;
  $('#baseValue').textContent = state.base;
  const hasFullKey = state.key && !state.key.includes('...');
  $('#keyValue').textContent = hasFullKey ? state.key : '请重新输入 Key 或上传凭证海报以显示完整 Key';
  $('#deviceValue').textContent = state.device || '未绑定设备凭证';
  let catalog = null;
  let modelError = '';
  try { catalog = await api('/api/guide/models'); } catch (error) { modelError = error.message; }
  setupModelPicker(catalog, modelError);
  document.querySelectorAll('[data-copy]').forEach(button => button.addEventListener('click', () => copyText($('#' + button.dataset.copy).textContent, button)));
  $('#logoutBtn').addEventListener('click', async () => {
    await fetch('/api/guide/logout', { method: 'POST', credentials: 'same-origin' }).catch(() => {});
    sessionStorage.removeItem('friendgate_guide_state');
    location.reload();
  });
}

$('#keyForm').addEventListener('submit', async event => {
  event.preventDefault(); setMessage('');
  const button = event.currentTarget.querySelector('button'); button.disabled = true;
  try { const data = await api('/api/guide/auth/key', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key: $('#keyInput').value.trim() }) }); saveState(data); await renderGuide(); }
  catch (error) { setMessage(error.message); }
  finally { button.disabled = false; }
});

$('#posterInput').addEventListener('change', async event => {
  const file = event.target.files?.[0]; if (!file) return;
  setMessage('正在验证海报隐藏签名…');
  const body = new FormData(); body.append('poster', file, file.name);
  try { const data = await api('/api/guide/auth/image', { method: 'POST', body }); saveState(data); await renderGuide(); }
  catch (error) { setMessage(error.message); event.target.value = ''; }
});

(async function init() {
  restoreState();
  try {
    const session = await api('/api/guide/session');
    if (!session.authenticated) return;
    // The session endpoint intentionally returns only a masked Key. Keep a
    // full value restored from sessionStorage/poster when available, while
    // still rendering every guide section after a refresh or a new tab.
    state.role = state.role || session.role || '';
    state.base = state.base || session.base_url || '';
    state.key = state.key || session.key || '';
    await renderGuide();
  } catch {}
})();
