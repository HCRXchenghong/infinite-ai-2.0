const state = {
  csrf: '',
  user: null,
  registration: true,
  invitationRequired: false,
  postgresAuthority: false,
  code: new URLSearchParams(location.search).get('code') || '',
  models: [],
  conversations: [],
  activeConversationId: '',
  pendingChat: false,
};

const $ = id => document.getElementById(id);

const flash = (message, ok = false) => {
  const node = $('flash');
  node.textContent = message;
  node.style.color = ok ? '#236746' : '';
  node.style.borderColor = ok ? '#b8dfca' : '';
  node.style.background = ok ? '#f1fbf5' : '';
  node.hidden = false;
  clearTimeout(flash.timer);
  flash.timer = setTimeout(() => node.hidden = true, 5000);
};

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body) headers['Content-Type'] = 'application/json';
  if (state.csrf && options.method && options.method !== 'GET') headers['X-CSRF-Token'] = state.csrf;
  const response = await fetch(path, { credentials: 'same-origin', cache: 'no-store', ...options, headers });
  let payload = {};
  try {
    payload = await response.json();
  } catch {}
  if (!response.ok) {
    const error = new Error(payload?.error?.message || `请求失败（${response.status}）`);
    error.status = response.status;
    error.payload = payload;
    error.conversationId = response.headers.get('X-Infinite-Conversation-ID') || '';
    throw error;
  }
  return payload;
}

function setMode(mode) {
  const login = mode === 'login';
  $('login-tab').classList.toggle('active', login);
  $('register-tab').classList.toggle('active', !login);
  $('login-form').hidden = !login;
  $('register-form').hidden = login;
  const title = $('auth-title');
  if (title) title.textContent = login ? '登录或注册' : '创建账号';
  const hint = $('auth-hint');
  if (hint) hint.textContent = state.code ? '登录后即可继续授权 Infinite AI 桌面设备。' : login ? '登录后可保存对话，并使用文件、图片等完整能力。' : '创建账号后即可使用 Infinite AI 的完整能力。';
  const copy = $('auth-switch-copy');
  if (copy) copy.textContent = login ? '还没有账号？' : '已经有账号？';
  const button = $('auth-switch-button');
  if (button) button.textContent = login ? '注册' : '登录';
}

function showLanding() {
  const view = $('landing-view');
  if (view) view.hidden = false;
  $('auth-view').hidden = true;
  $('account-view').hidden = true;
  document.body.classList.remove('auth-open');
}

function closeAuth() {
  showLanding();
}

function openAuth(mode = 'login') {
  showLanding();
  $('auth-view').hidden = false;
  document.body.classList.add('auth-open');
  setMode(mode);
  const first = $('auth-view').querySelector('input:not([disabled])');
  if (first) window.setTimeout(() => first.focus(), 20);
}

function showAuth() {
  state.user = null;
  showLanding();
  $('auth-hint').textContent = state.code ? '登录后即可继续授权 Infinite AI 桌面设备。' : '登录后可保存对话，并使用文件、图片等完整能力。';
  if (state.code) openAuth('login');
}

async function showAccount(payload) {
  state.user = payload.user;
  state.csrf = payload.csrf_token;
  $('landing-view').hidden = true;
  $('auth-view').hidden = true;
  $('account-view').hidden = false;
  document.body.classList.remove('auth-open');
  $('display-name').textContent = state.user.display_name;
  $('email').textContent = state.user.email;
  $('avatar').textContent = (state.user.display_name || 'I').slice(0, 1).toUpperCase();
  if (state.postgresAuthority) {
    $('approval-card').hidden = true;
    $('devices-card').hidden = true;
    $('platform-models-card').hidden = false;
    $('chat-card').hidden = false;
    await Promise.all([loadPlatformModels(), loadChatConversations()]);
    return;
  }
  $('platform-models-card').hidden = true;
  $('chat-card').hidden = true;
  await Promise.all([loadDevices(), loadFlow()]);
}

async function loadPlatformModels() {
  const root = $('platform-models');
  const select = $('chat-model');
  try {
    const payload = await api('/api/portal/models');
    root.textContent = '';
    select.textContent = '';
    state.models = Array.isArray(payload.items) ? payload.items : [];
    if (!state.models.length) {
      const empty = document.createElement('div');
      empty.className = 'empty';
      empty.textContent = '当前套餐没有已发布的 Chat 模型';
      root.append(empty);
      updateChatSendState();
      return;
    }
    let firstAvailable = '';
    for (const item of state.models) {
      const row = document.createElement('div');
      row.className = 'device';
      const info = document.createElement('div');
      const title = document.createElement('strong');
      title.textContent = item.display_name || item.model_key;
      const detail = document.createElement('small');
      detail.textContent = item.available ? `${item.model_key} · 已就绪` : `${item.model_key} · 后台正在配置可用路由`;
      info.append(title, detail);
      row.append(info);
      root.append(row);

      const option = document.createElement('option');
      option.value = item.model_key;
      option.textContent = item.display_name ? `${item.display_name} (${item.model_key})` : item.model_key;
      option.disabled = !item.available;
      select.append(option);
      if (item.available && !firstAvailable) firstAvailable = item.model_key;
    }
    if (firstAvailable && !select.value) select.value = firstAvailable;
    updateChatSendState();
  } catch (error) {
    root.textContent = '';
    const empty = document.createElement('div');
    empty.className = 'empty';
    empty.textContent = error.message;
    root.append(empty);
    state.models = [];
    select.textContent = '';
    updateChatSendState();
  }
}

async function loadChatConversations(selectFirst = true) {
  const root = $('chat-conversations');
  try {
    const payload = await api('/api/portal/chat/conversations');
    state.conversations = Array.isArray(payload.items) ? payload.items : [];
    renderConversationList();
    if (state.activeConversationId && state.conversations.some(item => item.id === state.activeConversationId)) {
      return;
    }
    if (selectFirst && state.conversations.length) {
      await selectConversation(state.conversations[0].id);
      return;
    }
    renderEmptyChat();
  } catch (error) {
    root.textContent = '';
    const empty = document.createElement('div');
    empty.className = 'empty';
    empty.textContent = error.message;
    root.append(empty);
  }
}

function renderConversationList() {
  const root = $('chat-conversations');
  root.textContent = '';
  if (!state.conversations.length) {
    const empty = document.createElement('div');
    empty.className = 'empty';
    empty.textContent = '还没有会话';
    root.append(empty);
    return;
  }
  for (const item of state.conversations) {
    const row = document.createElement('div');
    row.className = `conversation-item${item.id === state.activeConversationId ? ' active' : ''}`;
    const open = document.createElement('button');
    open.type = 'button';
    open.className = 'conversation-open';
    open.onclick = () => void selectConversation(item.id);
    const title = document.createElement('span');
    title.className = 'conversation-title';
    title.textContent = item.title || '新对话';
    const time = document.createElement('span');
    time.className = 'conversation-time';
    time.textContent = formatConversationTime(item.last_message_at || item.updated_at || item.created_at);
    open.append(title, time);
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'conversation-delete';
    remove.textContent = '×';
    remove.setAttribute('aria-label', '删除会话');
    remove.onclick = event => {
      event.stopPropagation();
      void deleteConversation(item.id, item.title || '新对话');
    };
    row.append(open, remove);
    root.append(row);
  }
}

function formatConversationTime(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}

async function selectConversation(id) {
  state.activeConversationId = id;
  renderConversationList();
  try {
    const payload = await api(`/api/portal/chat/conversations/${encodeURIComponent(id)}`);
    const conversation = payload.conversation || {};
    state.activeConversationId = conversation.id || id;
    $('chat-title').textContent = conversation.title || '新对话';
    if (conversation.selected_model_key && chatModelAvailable(conversation.selected_model_key)) {
      $('chat-model').value = conversation.selected_model_key;
    }
    renderMessages(Array.isArray(payload.messages) ? payload.messages : []);
    renderConversationList();
  } catch (error) {
    flash(error.message);
  }
}

function renderEmptyChat() {
  state.activeConversationId = '';
  $('chat-title').textContent = '新对话';
  renderConversationList();
  renderMessages([]);
}

async function deleteConversation(id, title) {
  if (!confirm(`删除“${title}”？`)) return;
  try {
    await api(`/api/portal/chat/conversations/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (state.activeConversationId === id) renderEmptyChat();
    await loadChatConversations();
    flash('会话已删除', true);
  } catch (error) {
    flash(error.message);
  }
}

function chatModelAvailable(modelKey) {
  return state.models.some(item => item.model_key === modelKey && item.available);
}

function updateChatSendState() {
  const send = $('chat-send');
  if (!send) return;
  send.disabled = state.pendingChat || !$('chat-model').value || !$('chat-input').value.trim();
}

function chatOutputText(payload) {
  if (typeof payload === 'string') return payload;
  if (typeof payload?.output_text === 'string' && payload.output_text) return payload.output_text;
  if (typeof payload?.text === 'string' && payload.text) return payload.text;
  const chunks = [];
  const scan = value => {
    if (!value || typeof value !== 'object') return;
    if (Array.isArray(value)) {
      value.forEach(scan);
      return;
    }
    if (typeof value.text === 'string') chunks.push(value.text);
    Object.values(value).forEach(scan);
  };
  scan(payload?.output);
  if (!chunks.length) scan(payload);
  return chunks.length ? chunks.join('\n') : JSON.stringify(payload, null, 2);
}

function messageText(message) {
  if (typeof message?.text === 'string' && message.text) return message.text;
  if (message?.content) return chatOutputText(message.content);
  return '';
}

function renderMessages(messages) {
  const root = $('chat-messages');
  root.textContent = '';
  if (!messages.length) {
    const empty = document.createElement('div');
    empty.className = 'empty';
    empty.textContent = '选择或开始一个对话';
    root.append(empty);
    return;
  }
  for (const message of messages) root.append(renderMessage(message));
  root.scrollTop = root.scrollHeight;
}

function appendRenderedMessage(message) {
  const root = $('chat-messages');
  const empty = root.querySelector('.empty');
  if (empty) root.textContent = '';
  root.append(renderMessage(message));
  root.scrollTop = root.scrollHeight;
}

function renderMessage(message) {
  const article = document.createElement('article');
  const role = message.role || 'assistant';
  article.className = `message ${role}${message.status === 'error' ? ' error' : ''}`;
  const roleNode = document.createElement('div');
  roleNode.className = 'message-role';
  roleNode.textContent = role === 'user' ? '你' : role === 'assistant' ? 'Infinite AI' : role;
  const body = document.createElement('div');
  body.className = 'message-body markdown';
  renderMarkdown(body, messageText(message));
  article.append(roleNode, body);
  return article;
}

async function sendChat(event) {
  event.preventDefault();
  const model = $('chat-model').value;
  const input = $('chat-input').value.trim();
  if (!model || !input || state.pendingChat) return;
  state.pendingChat = true;
  updateChatSendState();
  $('chat-input').value = '';
  appendRenderedMessage({ role: 'user', text: input, status: 'sent' });
  appendRenderedMessage({ role: 'assistant', text: '正在请求…', status: 'sent' });
  try {
    const path = state.activeConversationId
      ? `/api/portal/chat/conversations/${encodeURIComponent(state.activeConversationId)}/responses`
      : '/api/portal/chat/responses';
    const payload = await api(path, { method: 'POST', body: JSON.stringify({ model, input }) });
    const meta = payload.infinite_ai || {};
    const conversation = meta.conversation || payload.conversation;
    const messages = meta.messages || payload.messages;
    if (conversation?.id) {
      state.activeConversationId = conversation.id;
      $('chat-title').textContent = conversation.title || '新对话';
    }
    if (Array.isArray(messages)) {
      renderMessages(messages);
    } else {
      renderMessages([
        { role: 'user', text: input, status: 'sent' },
        { role: 'assistant', text: chatOutputText(payload), status: 'sent' },
      ]);
    }
    await loadChatConversations(false);
    renderConversationList();
  } catch (error) {
    const fallbackID = error.conversationId || error.payload?.infinite_ai?.conversation?.id || '';
    if (fallbackID) {
      state.activeConversationId = fallbackID;
      await selectConversation(fallbackID);
    } else {
      renderMessages([
        { role: 'user', text: input, status: 'sent' },
        { role: 'assistant', text: `请求失败：${error.message}`, status: 'error' },
      ]);
    }
    flash(error.message);
  } finally {
    state.pendingChat = false;
    updateChatSendState();
    $('chat-input').focus();
  }
}

function renderMarkdown(target, text) {
  target.textContent = '';
  const source = String(text || '');
  if (!source.trim()) return;
  const lines = source.replace(/\r\n?/g, '\n').split('\n');
  let index = 0;
  while (index < lines.length) {
    const line = lines[index];
    const trimmed = line.trim();
    if (!trimmed) {
      index++;
      continue;
    }
    if (trimmed.startsWith('```')) {
      const code = [];
      index++;
      while (index < lines.length && !lines[index].trim().startsWith('```')) {
        code.push(lines[index]);
        index++;
      }
      if (index < lines.length) index++;
      const pre = document.createElement('pre');
      const codeNode = document.createElement('code');
      codeNode.textContent = code.join('\n');
      pre.append(codeNode);
      target.append(pre);
      continue;
    }
    if (/^---+$|^\*\*\*+$/.test(trimmed)) {
      target.append(document.createElement('hr'));
      index++;
      continue;
    }
    const heading = trimmed.match(/^(#{1,3})\s+(.+)$/);
    if (heading) {
      const node = document.createElement(`h${heading[1].length}`);
      appendInline(node, heading[2]);
      target.append(node);
      index++;
      continue;
    }
    if (trimmed.startsWith('>')) {
      const quoteLines = [];
      while (index < lines.length && lines[index].trim().startsWith('>')) {
        quoteLines.push(lines[index].replace(/^\s*>\s?/, ''));
        index++;
      }
      const quote = document.createElement('blockquote');
      renderMarkdown(quote, quoteLines.join('\n'));
      target.append(quote);
      continue;
    }
    if (isTableStart(lines, index)) {
      const table = document.createElement('table');
      const thead = document.createElement('thead');
      const tbody = document.createElement('tbody');
      const header = document.createElement('tr');
      parseTableCells(lines[index]).forEach(cell => {
        const th = document.createElement('th');
        appendInline(th, cell);
        header.append(th);
      });
      thead.append(header);
      index += 2;
      while (index < lines.length && lines[index].includes('|') && lines[index].trim()) {
        const row = document.createElement('tr');
        parseTableCells(lines[index]).forEach(cell => {
          const td = document.createElement('td');
          appendInline(td, cell);
          row.append(td);
        });
        tbody.append(row);
        index++;
      }
      table.append(thead, tbody);
      target.append(table);
      continue;
    }
    const listMatch = line.match(/^\s*(?:[-*+]\s+|\d+[.)]\s+)/);
    if (listMatch) {
      const ordered = /^\s*\d+[.)]\s+/.test(line);
      const list = document.createElement(ordered ? 'ol' : 'ul');
      const pattern = ordered ? /^\s*\d+[.)]\s+(.+)$/ : /^\s*[-*+]\s+(.+)$/;
      while (index < lines.length) {
        const match = lines[index].match(pattern);
        if (!match) break;
        const item = document.createElement('li');
        appendInline(item, match[1]);
        list.append(item);
        index++;
      }
      target.append(list);
      continue;
    }
    const paragraph = [trimmed];
    index++;
    while (index < lines.length && lines[index].trim() && !isMarkdownBlockStart(lines, index)) {
      paragraph.push(lines[index].trim());
      index++;
    }
    const p = document.createElement('p');
    appendInline(p, paragraph.join(' '));
    target.append(p);
  }
}

function isMarkdownBlockStart(lines, index) {
  const line = lines[index] || '';
  const trimmed = line.trim();
  return trimmed.startsWith('```') ||
    /^---+$|^\*\*\*+$/.test(trimmed) ||
    /^(#{1,3})\s+/.test(trimmed) ||
    trimmed.startsWith('>') ||
    /^\s*(?:[-*+]\s+|\d+[.)]\s+)/.test(line) ||
    isTableStart(lines, index);
}

function isTableStart(lines, index) {
  return index + 1 < lines.length &&
    lines[index].includes('|') &&
    /^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$/.test(lines[index + 1]);
}

function parseTableCells(line) {
  return line.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map(cell => cell.trim());
}

function appendInline(parent, text) {
  const source = String(text || '');
  const token = /(`([^`]+)`|\*\*([^*]+)\*\*|\*([^*]+)\*|\[([^\]]+)\]\(([^)\s]+)\))/g;
  let index = 0;
  let match;
  while ((match = token.exec(source))) {
    if (match.index > index) parent.append(document.createTextNode(source.slice(index, match.index)));
    if (match[2] !== undefined) {
      const code = document.createElement('code');
      code.textContent = match[2];
      parent.append(code);
    } else if (match[3] !== undefined) {
      const strong = document.createElement('strong');
      appendInline(strong, match[3]);
      parent.append(strong);
    } else if (match[4] !== undefined) {
      const em = document.createElement('em');
      appendInline(em, match[4]);
      parent.append(em);
    } else if (match[5] !== undefined && match[6] !== undefined) {
      const link = safeLink(match[5], match[6]);
      parent.append(link);
    }
    index = token.lastIndex;
  }
  if (index < source.length) parent.append(document.createTextNode(source.slice(index)));
}

function safeLink(label, href) {
  try {
    const url = new URL(href, location.href);
    if (url.protocol === 'http:' || url.protocol === 'https:') {
      const link = document.createElement('a');
      link.href = url.href;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      link.textContent = label;
      return link;
    }
  } catch {}
  return document.createTextNode(label);
}

async function loadFlow() {
  if (!state.code) {
    $('approval-card').hidden = true;
    return;
  }
  try {
    const flow = await api(`/api/portal/device-flow?code=${encodeURIComponent(state.code)}`);
    if (flow.status === 'pending') {
      $('device-name').textContent = flow.device_name;
      $('device-platform').textContent = flow.platform || '未知平台';
      $('device-ip').textContent = flow.request_ip;
      $('user-code').textContent = state.code;
      $('approval-card').hidden = false;
      $('approved-card').hidden = true;
    } else {
      $('approval-card').hidden = true;
      $('approved-card').hidden = false;
    }
  } catch (error) {
    $('approval-card').hidden = true;
    flash(error.message);
  }
}

async function loadDevices() {
  try {
    const payload = await api('/api/portal/devices');
    const root = $('devices');
    root.textContent = '';
    if (!payload.items?.length) {
      const empty = document.createElement('div');
      empty.className = 'empty';
      empty.textContent = '还没有已授权的桌面设备';
      root.append(empty);
      return;
    }
    for (const item of payload.items) {
      const row = document.createElement('div');
      row.className = 'device';
      const info = document.createElement('div');
      const title = document.createElement('strong');
      title.textContent = item.name;
      const detail = document.createElement('small');
      detail.textContent = `${item.platform || '未知系统'} · MAC ${item.mac || '未读取'} · 最近 IP ${item.last_ip || item.registered_ip} · ${item.status === 'active' ? '已授权' : '已退出'}`;
      info.append(title, detail);
      row.append(info);
      if (item.status === 'active') {
        const button = document.createElement('button');
        button.type = 'button';
        button.textContent = '立即退出';
        button.onclick = async () => {
          if (!confirm(`确认让“${item.name}”立即退出？`)) return;
          button.disabled = true;
          try {
            await api(`/api/portal/devices/${item.id}`, { method: 'DELETE' });
            flash('设备已立即退出', true);
            await loadDevices();
          } catch (error) {
            flash(error.message);
            button.disabled = false;
          }
        };
        row.append(button);
      }
      root.append(row);
    }
  } catch (error) {
    const root = $('devices');
    root.textContent = '';
    const empty = document.createElement('div');
    empty.className = 'empty';
    empty.textContent = error.message;
    root.append(empty);
  }
}

async function submitAuth(form, path) {
  const button = form.querySelector('button[type=submit]');
  button.disabled = true;
  try {
    const values = Object.fromEntries(new FormData(form));
    const payload = await api(path, { method: 'POST', body: JSON.stringify(values) });
    await showAccount(payload);
  } catch (error) {
    flash(error.message);
  } finally {
    button.disabled = false;
  }
}

$('login-tab').onclick = () => setMode('login');
$('register-tab').onclick = () => setMode('register');
$('auth-switch-button').onclick = () => setMode($('login-form').hidden ? 'login' : 'register');
$('auth-close').onclick = closeAuth;
$('auth-backdrop').onclick = closeAuth;
$('auth-view').addEventListener('keydown', event => { if (event.key === 'Escape') closeAuth(); });
$('landing-view').querySelectorAll('[data-auth-mode]').forEach(button => button.addEventListener('click', () => openAuth(button.dataset.authMode || 'login')));

const collapseButton = document.querySelector('.landing-collapse');
if (collapseButton) {
  collapseButton.onclick = () => {
    const shell = $('landing-view');
    const collapsed = shell.classList.toggle('is-collapsed');
    collapseButton.setAttribute('aria-label', collapsed ? '展开侧栏' : '收起侧栏');
  };
}

$('login-form').onsubmit = event => {
  event.preventDefault();
  void submitAuth(event.currentTarget, '/api/portal/login');
};
$('register-form').onsubmit = event => {
  event.preventDefault();
  void submitAuth(event.currentTarget, '/api/portal/register');
};
$('chat-form').onsubmit = event => { void sendChat(event); };
$('chat-input').addEventListener('input', updateChatSendState);
$('chat-model').addEventListener('change', updateChatSendState);
$('new-chat').onclick = () => {
  renderEmptyChat();
  $('chat-input').focus();
};
$('approve').onclick = async () => {
  const button = $('approve');
  button.disabled = true;
  try {
    await api('/api/portal/device-flow/approve', { method: 'POST', body: JSON.stringify({ user_code: state.code }) });
    $('approval-card').hidden = true;
    $('approved-card').hidden = false;
    flash('设备授权成功，可以返回 Infinite AI', true);
    await loadDevices();
  } catch (error) {
    flash(error.message);
    button.disabled = false;
  }
};
$('logout').onclick = async () => {
  try {
    await api('/api/portal/logout', { method: 'POST' });
    state.csrf = '';
    state.activeConversationId = '';
    state.conversations = [];
    history.replaceState({}, '', location.pathname);
    state.code = '';
    showAuth();
  } catch (error) {
    flash(error.message);
  }
};
$('refresh-devices').onclick = () => void loadDevices();
const refreshModels = $('refresh-platform-models');
if (refreshModels) refreshModels.onclick = () => void loadPlatformModels();

async function boot() {
  try {
    const [config, me] = await Promise.all([api('/api/portal/config'), api('/api/portal/me')]);
    state.registration = config.registration_enabled;
    state.invitationRequired = Boolean(config.invitation_required);
    state.postgresAuthority = config.product_authority === 'postgresql';
    $('register-tab').hidden = !state.registration;
    document.querySelectorAll('[data-auth-mode="register"]').forEach(el => { el.hidden = !state.registration; });
    const inviteFields = $('invitation-fields');
    if (inviteFields) {
      inviteFields.hidden = !state.invitationRequired;
      $('invitation-token').required = state.invitationRequired;
      $('invitation-code').required = state.invitationRequired;
    }
    const footer = document.querySelector('.auth-footer');
    if (footer) footer.hidden = !state.registration;
    if (!state.registration) setMode('login');
    if (me.authenticated) await showAccount(me);
    else showAuth();
  } catch (error) {
    showAuth();
    flash(error.message);
  }
}

void boot();
