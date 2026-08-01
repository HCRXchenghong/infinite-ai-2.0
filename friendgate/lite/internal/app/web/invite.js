const token = new URLSearchParams(location.search).get('invite') || '';
const $ = selector => document.querySelector(selector);
let revealUntil = 0;
let timerHandle;
let redirecting = false;
let deviceToken = '';
let observedIPs = [];
let inviteRole = '';
let issuedKey = '';
let issuedBaseURL = '';
let issuedGuideURL = '';
let guideToken = '';

async function api(path, options = {}) {
  options.headers = { ...(options.headers || {}) };
  if (options.body) options.headers['Content-Type'] = 'application/json';
  const response = await fetch(path, options);
  let data = {};
  try { data = await response.json(); } catch {}
  if (!response.ok) throw new Error(data?.error?.message || '请求失败');
  return data;
}

function step(name, index) {
  ['#invalid', '#verifyStep', '#deviceStep', '#generateStep', '#keyStep'].forEach(id => $(id).classList.add('hidden'));
  $(name).classList.remove('hidden');
  document.querySelectorAll('.dot').forEach((item, i) => item.classList.toggle('active', i <= index));
}

function message(text) {
  const element = $('#message');
  element.textContent = text;
  element.classList.toggle('hidden', !text);
}

function normalizedIPs(items) {
  const found = new Map();
  for (const item of items || []) {
    if (item?.ip) found.set(item.ip, item);
  }
  return [...found.values()].sort((a, b) => String(a.family).localeCompare(String(b.family)));
}

function renderIPs(items) {
  const values = normalizedIPs(items);
  $('#ips').innerHTML = values.length
    ? values.map(item => `<div><span class="ip-family">${item.family === 'ipv6' ? 'IPv6' : 'IPv4'}</span>${escapeHTML(item.ip)}</div>`).join('')
    : '<span class="muted">未检测到公网地址</span>';
}

function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}

async function probeAddress(baseURL, probeToken) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  try {
    const base = String(baseURL || '').replace(/\/$/, '');
    const response = await fetch(`${base}/api/invitations/${encodeURIComponent(token)}/probe`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ probe_token: probeToken }),
      credentials: 'omit',
      signal: controller.signal
    });
    if (!response.ok) return [];
    const data = await response.json();
    return data.ips || [];
  } catch {
    return [];
  } finally {
    clearTimeout(timeout);
  }
}

async function detectDualStack(data) {
  let ips = normalizedIPs(data.ips || []);
  renderIPs(ips);
  const probes = [...new Set(data.probe_urls || [])];
  if (!data.probe_token || !probes.length) return ips;
  $('#ipHint').textContent = '正在分别检测 IPv4 和 IPv6…';
  const results = await Promise.allSettled(probes.map(url => probeAddress(url, data.probe_token)));
  for (const result of results) {
    if (result.status === 'fulfilled') ips = normalizedIPs([...ips, ...result.value]);
  }
  renderIPs(ips);
  const families = new Set(ips.map(item => item.family));
  $('#ipHint').textContent = families.size > 1 ? '已检测到双栈地址，两个地址都会加入白名单。' : '当前网络只检测到一个公网协议地址。';
  return ips;
}

async function init() {
  if (token.length < 20) return invalid('邀请链接不完整。');
  try {
    const info = await api(`/api/invitations/${encodeURIComponent(token)}`);
    inviteRole = info.role || '';
    $('#role').textContent = info.role;
    $('#intro').textContent = `${info.role}，请完成验证后领取专属 Key。${info.binding_mode === 'device' ? '此邀请使用设备凭证绑定，动态 IP 不影响调用。' : info.binding_mode === 'ip_device' ? '此邀请同时绑定公网 IP 与设备凭证。' : ''}`;
    if (info.status === 'claimed') {
      if (!info.verified) return invalid('这个邀请已经被使用。');
      observedIPs = normalizedIPs(info.ips || []);
      return showKey(await api(`/api/invitations/${encodeURIComponent(token)}/key`));
    }
    if (info.verified) {
      observedIPs = normalizedIPs(info.ips || []);
      renderIPs(observedIPs);
      $('#ipHint').textContent = '已恢复本次领取会话记录的公网地址。';
      $('#deviceNote').value = info.device_note || '';
      return step('#deviceStep', 1);
    }
    step('#verifyStep', 0);
  } catch (error) {
    invalid(error.message);
  }
}

function invalid(text) {
  $('#role').textContent = '邀请不可用';
  $('#intro').textContent = '无法继续领取';
  $('#invalidText').textContent = text;
  step('#invalid', 0);
}

$('#verifyStep').addEventListener('submit', async event => {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"], button:not([type])');
  if (button?.disabled) return;
  if (button) button.disabled = true;
  message('');
  try {
    const data = await api(`/api/invitations/${encodeURIComponent(token)}/verify`, {
      method: 'POST',
      body: JSON.stringify({ code: $('#code').value })
    });
    step('#deviceStep', 1);
    observedIPs = await detectDualStack(data);
  } catch (error) {
    message(error.message);
  } finally {
    if (button) button.disabled = false;
  }
});

$('#deviceStep').addEventListener('submit', async event => {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"], button:not([type])');
  if (button?.disabled) return;
  if (button) button.disabled = true;
  message('');
  try {
    const data = await api(`/api/invitations/${encodeURIComponent(token)}/device`, {
      method: 'POST',
      body: JSON.stringify({ device_note: $('#deviceNote').value })
    });
    deviceToken = data.device_token || '';
    step('#generateStep', 2);
  } catch (error) {
    message(error.message);
  } finally {
    if (button) button.disabled = false;
  }
});

$('#generateBtn').addEventListener('click', async () => {
  message('');
  $('#generateBtn').disabled = true;
  try {
    showKey(await api(`/api/invitations/${encodeURIComponent(token)}/generate`, { method: 'POST', body: '{}' }), true);
  } catch (error) {
    message(error.message);
    $('#generateBtn').disabled = false;
  }
});

function showKey(data, autoDownload = false) {
  issuedKey = data.key || '';
  issuedBaseURL = data.base_url || '';
  issuedGuideURL = data.guide_url || '';
  guideToken = data.guide_token || '';
  $('#keyValue').textContent = issuedKey;
  $('#baseURL').textContent = issuedBaseURL;
  $('#deviceTokenValue').textContent = deviceToken || '—';
  $('#ipValue').textContent = observedIPs.length ? observedIPs.map(item => `${item.family === 'ipv6' ? 'IPv6' : 'IPv4'} ${item.ip}`).join(' · ') : '未检测到公网 IP';
  revealUntil = data.reveal_until;
  step('#keyStep', 2);
  const retryButton = $('#retryPosterBtn');
  retryButton.classList.add('hidden');
  retryButton.disabled = false;
  $('#downloadPosterBtn').disabled = false;
  $('#downloadPosterBtn').textContent = '一键下载凭证海报';
  updateTimer();
  clearInterval(timerHandle);
  timerHandle = setInterval(updateTimer, 1000);
  // A newly generated credential is downloaded immediately. Browsers may block
  // an automatic download, so the explicit retry action remains available.
  if (autoDownload) setTimeout(() => downloadPoster(true), 80);
}

function roundedRect(ctx, x, y, width, height, radius) {
  const r = Math.min(radius, width / 2, height / 2);
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + width, y, x + width, y + height, r);
  ctx.arcTo(x + width, y + height, x, y + height, r);
  ctx.arcTo(x, y + height, x, y, r);
  ctx.arcTo(x, y, x + width, y, r);
  ctx.closePath();
}

function drawPosterText(ctx, text, x, y, maxWidth, lineHeight, maxLines = 4) {
  const value = String(text || '—');
  const lines = [];
  let line = '';
  for (const character of value) {
    const candidate = line + character;
    if (line && ctx.measureText(candidate).width > maxWidth) {
      lines.push(line);
      line = character;
      if (lines.length >= maxLines - 1) break;
    } else {
      line = candidate;
    }
  }
  if (line && lines.length < maxLines) lines.push(line);
  if (lines.length === maxLines && value.length > lines.join('').length) {
    lines[maxLines - 1] = `${lines[maxLines - 1].slice(0, -1)}…`;
  }
  lines.forEach((item, index) => ctx.fillText(item, x, y + index * lineHeight));
  return y + lines.length * lineHeight;
}

function buildCredentialPoster() {
  const canvas = document.createElement('canvas');
  const width = 1400;
  const height = 1040;
  const scale = Math.min(2, window.devicePixelRatio || 1);
  canvas.width = width * scale;
  canvas.height = height * scale;
  const ctx = canvas.getContext('2d');
  ctx.scale(scale, scale);

  const background = ctx.createLinearGradient(0, 0, width, height);
  background.addColorStop(0, '#eaf5fa');
  background.addColorStop(1, '#c4dfea');
  ctx.fillStyle = background;
  ctx.fillRect(0, 0, width, height);

  ctx.fillStyle = '#174a68';
  ctx.font = '700 42px ui-sans-serif, system-ui, -apple-system, "PingFang SC", sans-serif';
  ctx.fillText('FriendGate', 78, 88);
  ctx.fillStyle = '#5e7d8d';
  ctx.font = '500 20px ui-sans-serif, system-ui, -apple-system, "PingFang SC", sans-serif';
  ctx.fillText('PRIVATE CODEX ACCESS · 凭证海报', 80, 124);
  ctx.fillStyle = '#2f83ae';
  ctx.fillRect(80, 150, 1240, 5);

  roundedRect(ctx, 80, 190, 1240, 120, 20);
  ctx.fillStyle = '#1c5d7e';
  ctx.fill();
  ctx.fillStyle = '#bfe4f2';
  ctx.font = '600 20px ui-sans-serif, system-ui, -apple-system, "PingFang SC", sans-serif';
  ctx.fillText('受邀昵称', 120, 236);
  ctx.fillStyle = '#ffffff';
  ctx.font = '700 34px ui-sans-serif, system-ui, -apple-system, "PingFang SC", sans-serif';
  ctx.fillText(inviteRole || 'FriendGate 用户', 120, 280);
  ctx.fillStyle = '#bfe4f2';
  ctx.font = '500 18px ui-sans-serif, system-ui, -apple-system, "PingFang SC", sans-serif';
  ctx.fillText(`生成时间：${new Date().toLocaleString()}`, 880, 264);

  const fields = [
    ['API Key', issuedKey || '—'],
    ['设备凭证', deviceToken || '—'],
    ['受邀时使用的 IP', observedIPs.length ? observedIPs.map(item => `${item.family === 'ipv6' ? 'IPv6' : 'IPv4'}  ${item.ip}`).join('    ') : '未检测到公网 IP'],
    ['API Base URL', issuedBaseURL || '—'],
    ['配置指南', issuedGuideURL || '—']
  ];
  let y = 355;
  fields.forEach(([label, value], index) => {
    roundedRect(ctx, 80, y, 1240, index === 2 ? 112 : 92, 16);
    ctx.fillStyle = '#ffffff';
    ctx.fill();
    ctx.strokeStyle = '#b4d1df';
    ctx.lineWidth = 2;
    ctx.stroke();
    ctx.fillStyle = '#5d7b8a';
    ctx.font = '600 18px ui-sans-serif, system-ui, -apple-system, "PingFang SC", sans-serif';
    ctx.fillText(label, 116, y + 32);
    ctx.fillStyle = '#1f4f69';
    ctx.font = index === 2 ? '500 22px ui-monospace, SFMono-Regular, Consolas, monospace' : '600 22px ui-monospace, SFMono-Regular, Consolas, monospace';
    drawPosterText(ctx, value, 116, y + 67, 1160, 28, index === 2 ? 2 : 2);
    y += index === 2 ? 132 : 112;
  });

  ctx.fillStyle = '#557789';
  ctx.font = '500 17px ui-sans-serif, system-ui, -apple-system, "PingFang SC", sans-serif';
  ctx.fillText('请将此图片保存到安全位置。Key 与设备凭证等同于访问密码，切勿转发。', 80, 990);
  embedGuideMarker(canvas, { v: 1, t: guideToken, k: issuedKey, d: deviceToken });
  return canvas;
}

// Store a signed, lossless marker in RGB least-significant bits. It is
// visually imperceptible, survives the PNG download, and is decoded by the
// dedicated guide listener rather than trusting OCR or user-editable text.
function embedGuideMarker(canvas, marker) {
  if (!marker?.t || !marker?.k) return;
  const payload = new TextEncoder().encode(JSON.stringify(marker));
  if (payload.length > 4095) return;
  const frame = new Uint8Array(6 + payload.length);
  frame.set([0x46, 0x47, 0x50, 0x31, (payload.length >> 8) & 0xff, payload.length & 0xff]);
  frame.set(payload, 6);
  const ctx = canvas.getContext('2d');
  const rowY = canvas.height - 1;
  const pixels = ctx.getImageData(0, rowY, canvas.width, 1);
  const needed = Math.ceil(frame.length * 8 / 3);
  if (needed > canvas.width) return;
  let bitIndex = 0;
  for (let x = 0; x < needed; x++) {
    const offset = x * 4;
    for (let channel = 0; channel < 3; channel++) {
      const bit = bitIndex < frame.length * 8
        ? (frame[Math.floor(bitIndex / 8)] >> (7 - (bitIndex % 8))) & 1
        : 0;
      pixels.data[offset + channel] = (pixels.data[offset + channel] & 0xfe) | bit;
      bitIndex++;
    }
  }
  ctx.putImageData(pixels, 0, rowY);
}

async function downloadPoster(automatic = false) {
  if (!issuedKey || redirecting) return;
  const button = $('#downloadPosterBtn');
  const retryButton = $('#retryPosterBtn');
  button.disabled = true;
  retryButton.disabled = true;
  button.textContent = '正在生成海报…';
  try {
    const canvas = buildCredentialPoster();
    const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/png'));
    if (!blob) throw new Error('浏览器不支持图片导出');
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `friendgate-${(inviteRole || 'credential').replace(/[^\w\u4e00-\u9fff-]+/g, '_')}.png`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    button.textContent = '再次下载凭证海报';
    retryButton.classList.remove('hidden');
    message(automatic
      ? '已触发 PNG 下载；如果浏览器没有保存，请点击“没有下载？重试”。'
      : '已再次触发 PNG 下载，请检查浏览器下载记录。');
  } catch (error) {
    message(error.message || '海报生成失败');
    button.textContent = '一键下载凭证海报';
    retryButton.classList.remove('hidden');
  } finally {
    if (!redirecting) {
      button.disabled = false;
      retryButton.disabled = false;
    }
  }
}

function updateTimer() {
  const left = Math.max(0, revealUntil - Math.floor(Date.now() / 1000));
  $('#timer').textContent = String(left).padStart(2, '0');
  if (left <= 0) expireAndRedirect();
}

async function expireAndRedirect() {
  if (redirecting) return;
  redirecting = true;
  clearInterval(timerHandle);
  $('#keyValue').textContent = '邀请链接已永久失效';
  $('#copyBtn').disabled = true;
  $('#downloadPosterBtn').disabled = true;
  $('#retryPosterBtn').disabled = true;
  try {
    await fetch(`/api/invitations/${encodeURIComponent(token)}/close`, { method: 'POST', keepalive: true });
  } catch {}
  location.replace('https://www.bing.com/');
}

$('#copyBtn').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText($('#keyValue').textContent);
    $('#copyBtn').textContent = '已复制';
  } catch {
    $('#keyValue').scrollIntoView();
    message('浏览器无法自动复制，请长按 Key 手动复制');
  }
});

$('#downloadPosterBtn').addEventListener('click', () => downloadPoster(false));
$('#retryPosterBtn').addEventListener('click', () => downloadPoster(false));

window.addEventListener('pageshow', event => {
  if (event.persisted && revealUntil > 0 && Math.floor(Date.now() / 1000) >= revealUntil) {
    location.replace('https://www.bing.com/');
  }
});

init();
