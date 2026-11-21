'use strict';
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const invoke = (name, args) => {
  if (!window.__TAURI__?.core?.invoke) return Promise.reject(new Error('Откройте KasperVPN как Tauri-приложение, а не в браузере.'));
  return window.__TAURI__.core.invoke(name, args);
};
let connected = false;
let busy = false;
let polling = false;
let probing = false;
let accountBusy = false;
let dirty = false;
let toastTimer;
let lastError = '';
let settingsCache = null;
function notify(message, error = false) {
  clearTimeout(toastTimer);
  const node = $('#toast');
  node.textContent = String(message);
  node.classList.toggle('error', error);
  node.hidden = false;
  toastTimer = setTimeout(() => { node.hidden = true; }, error ? 14000 : 4500);
}
function tab(id) {
  $$('.page').forEach((page) => { page.hidden = page.id !== id; });
  $$('.nav').forEach((button) => {
    const selected = button.dataset.tab === id;
    button.classList.toggle('active', selected);
    button.setAttribute('aria-selected', String(selected));
  });
}
$$('.nav').forEach((button) => button.addEventListener('click', () => tab(button.dataset.tab)));
function collect() {
  return {
    ...(settingsCache || {}),
    key: $('#vless-key').value.trim(),
    applications: $$('input[name="application"]:checked').map((input) => input.value),
    domains: $('#domains').value,
    mode: $('input[name="mode"]:checked').value,
    singBoxPath: $('#sing-box-path').value.trim() || 'sing-box',
    mtprotoPort: Number($('#mtproto-port').value) || (settingsCache?.mtprotoPort ?? 17893),
    mtprotoSecret: settingsCache?.mtprotoSecret || '',
  };
}
function countDomains() {
  $('#domain-count').textContent = `${$('#domains').value.split('\n').filter((line) => line.trim() && !line.trim().startsWith('#')).length} ДОМЕНОВ`;
}
function populate(settings) {
  settingsCache = settings;
  $('#vless-key').value = settings.key || '';
  $('#domains').value = settings.domains;
  $('#sing-box-path').value = settings.singBoxPath;
  $('#mtproto-port').value = settings.mtprotoPort || 17893;
  $$('input[name="application"]').forEach((input) => { input.checked = settings.applications.includes(input.value); });
  $$('input[name="mode"]').forEach((input) => { input.checked = settings.mode === input.value; });
  countDomains();
  refreshMtproto();
}
async function refreshMtproto() {
  try {
    const link = await invoke('mtproto_link');
    $('#mtproto-link').value = link.link || '';
    $('#copy-mtproto').disabled = !link.link;
    $('#mtproto-status').textContent = link.running
      ? 'MTProto-сервер запущен — Telegram в этой сети может подключаться по ссылке.'
      : 'Сервер не запущен: включите режим «Telegram · MTProto» и подключитесь.';
  } catch (_) { /* поле остаётся пустым до первого запуска */ }
}
async function save() {
  const buttons = $$('.save-settings');
  buttons.forEach((button) => { button.disabled = true; });
  try {
    await invoke('save_settings', { settings: collect() });
    dirty = false;
    buttons.forEach((button) => { button.textContent = 'Сохранить настройки'; });
    notify(connected ? 'Сохранено. Переподключитесь для применения изменений.' : 'Настройки сохранены на устройстве.');
  } catch (error) { notify(error, true); }
  finally { buttons.forEach((button) => { button.disabled = false; }); }
}
$$('.save-settings').forEach((button) => button.addEventListener('click', save));
$$('input, textarea').forEach((input) => input.addEventListener('input', () => {
  dirty = true;
  $$('.save-settings').forEach((button) => { button.textContent = 'Сохранить изменения •'; });
  countDomains();
}));
$('#show-key').addEventListener('click', () => {
  const hidden = $('#vless-key').type === 'password';
  $('#vless-key').type = hidden ? 'text' : 'password';
  $('#show-key').textContent = hidden ? 'Скрыть' : 'Показать';
});

async function loadAccount() {
  try {
    const account = await invoke('current_account');
    $('#account-form').hidden = true;
    $('#account-profile').hidden = false;
    $('#account-name').textContent = account.username;
    $('#account-usage').textContent = `${account.usedGB} / ${account.totalGB} ГБ · ${account.percentage}%`;
    $('#account-created').textContent = `Аккаунт с ${account.createdAt}`;
    $('#account-vless').value = account.vlessLink;
    $('#account-error').textContent = '';
    $('#copy-vless').disabled = false;
  } catch (_) {
    $('#account-form').hidden = false;
    $('#account-profile').hidden = true;
    $('#copy-vless').disabled = true;
  }
}

$('#account-login').addEventListener('click', async () => {
  if (accountBusy) return;
  accountBusy = true;
  $('#account-login').disabled = true;
  $('#account-error').textContent = '';
  try {
    await invoke('login_account', { username: $('#account-username').value, password: $('#account-password').value });
    $('#account-password').value = '';
    await loadAccount();
    const profile = await invoke('current_account');
    $('#vless-key').value = profile.vlessLink;
    $('#vless-key').dispatchEvent(new Event('input'));
    notify('Вход выполнен. VLESS-ссылка загружена. Сохраните настройки.');
  } catch (error) { $('#account-error').textContent = String(error); }
  finally { accountBusy = false; $('#account-login').disabled = false; }
});

$('#account-logout').addEventListener('click', async () => {
  if (accountBusy) return;
  accountBusy = true;
  $('#account-logout').disabled = true;
  try {
    await invoke('logout_account');
    await invoke('clear_account_vless');
    $('#account-vless').value = '';
    $('#vless-key').value = '';
    await loadAccount();
    notify('Вы вышли. Загруженная VLESS-ссылка очищена.');
  } catch (error) { notify(error, true); }
  finally { accountBusy = false; $('#account-logout').disabled = false; }
});

$('#copy-vless').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText($('#account-vless').value);
    $('#vless-key').value = $('#account-vless').value;
    $('#vless-key').dispatchEvent(new Event('input'));
    notify('VLESS-ссылка скопирована и добавлена в поле подключения. Сохраните настройки.');
  } catch (error) { notify(`Не удалось скопировать ссылку: ${error}`, true); }
});
$('#sync-domains').addEventListener('click', async () => {
  const button = $('#sync-domains');
  button.disabled = true;
  button.textContent = '↻ Синхронизация…';
  try {
    const result = await invoke('update_domains_from_zapret');
    const existing = $('#domains').value.split('\n').map((line) => line.trim()).filter(Boolean);
    $('#domains').value = [...new Set([...existing, ...result.domains])].join('\n');
    $('#domains').dispatchEvent(new Event('input'));
    $('#sync-result').textContent = result.warning || `Обновлено из ${result.source === 'github' ? 'GitHub' : 'локального кэша'}: ${result.domains.length} доменов. Ваши домены сохранены. Нажмите «Сохранить настройки».`;
    notify(result.warning || 'Список Запрета обновлён.');
  } catch (error) { notify(error, true); }
  finally { button.disabled = false; button.textContent = '↻ Обновить из Запрета'; }
});
function bytes(value) {
  let amount = Number(value) || 0;
  const units = ['Б', 'КБ', 'МБ', 'ГБ'];
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) { amount /= 1024; unit++; }
  return `${amount.toFixed(unit ? 1 : 0)} ${units[unit]}`;
}
function speed(id, value) {
  const [amount, unit] = bytes(value).split(' ');
  $(id).replaceChildren(document.createTextNode(`${amount} `));
  const em = document.createElement('em'); em.textContent = `${unit}/с`; $(id).append(em);
}
function render(status) {
  connected = status.connected;
  document.body.classList.toggle('connected', connected);
  $('#connection-badge').classList.toggle('connected', connected);
  $('#connection-badge').textContent = connected ? 'Подключено' : 'Отключено';
  $('#connection-title').textContent = connected ? 'Канал активен' : 'Готов к подключению';
  $('#connection-description').textContent = connected ? 'Выбранный трафик направляется через VPN' : 'Нажмите, чтобы открыть защищённый канал';
  $('#connect-label').textContent = connected ? 'ОТКЛЮЧИТЬ' : 'ПОДКЛЮЧИТЬ';
  $('#power').setAttribute('aria-label', connected ? 'Отключить VPN' : 'Подключить VPN');
  $('#power').setAttribute('aria-pressed', String(connected));
  $('#ip').textContent = connected ? status.ip || 'Проверяем…' : '—';
  $('#ping').replaceChildren(document.createTextNode(connected && status.ping != null ? `${status.ping} ` : '— '));
  const unit = document.createElement('em'); unit.textContent = 'мс'; $('#ping').append(unit);
  speed('#download', connected ? status.downloadSpeed : 0);
  speed('#upload', connected ? status.uploadSpeed : 0);
  $('#download-total').textContent = `Получено: ${bytes(status.downloadBytes)}`;
  $('#upload-total').textContent = `Отправлено: ${bytes(status.uploadBytes)}`;
  const seconds = status.uptime || 0;
  $('#uptime').textContent = [Math.floor(seconds / 3600), Math.floor(seconds / 60) % 60, seconds % 60].map((part) => String(part).padStart(2, '0')).join(':');
  const tun = status.mode === 'tun';
  const system = status.mode === 'system';
  const telegram = status.mode === 'telegram';
  $('#mode-label').textContent = tun ? 'TUN · SPLIT TUNNEL' : system ? 'VPN · СИСТЕМНЫЙ ПРОКСИ' : telegram ? 'TELEGRAM · MTPROTO' : 'VPN · СИСТЕМНЫЙ ПРОКСИ';
  $('#network-hint').textContent = tun ? 'TUN активен: выбранные приложения и домены идут через VLESS, остальной трафик напрямую.' : system ? 'Системный прокси → 127.0.0.1:17890 → VLESS. Применяются все доступные механизмы окружения (Linux: gsettings, dconf-портал, KDE kioslaverc, systemd user env, environment.d — независимо от DE/WM; Windows: реестр + WinINet; macOS: networksetup). При отключении прежние настройки восстанавливаются. Уже запущенные приложения и текущий терминал нужно перезапустить, а программы со своим прокси или сырым сокетом системную настройку игнорируют.' : telegram ? 'MTProto-сервер 127.0.0.1:' + (settingsCache?.mtprotoPort || 17893) + ' → VLESS. Добавьте прокси в Telegram по ссылке tg://proxy — можно с телефона в этой же сети. Системный прокси не затрагивается.' : 'VPN → системный прокси на 127.0.0.1:17890 → удалённый VLESS-сервер.';
  $('#footer-status').textContent = connected ? 'Защищённый канал активен' : 'Прямое соединение';
  if (status.error && status.error !== lastError) { notify(status.error, true); lastError = status.error; }
}
async function poll() {
  if (polling || busy) return;
  polling = true;
  try { render(await invoke('get_status')); }
  catch (error) { if (String(error) !== lastError) { notify(error, true); lastError = String(error); } }
  finally { polling = false; }
}
async function probe() {
  if (probing || !connected || busy) return;
  probing = true;
  try {
    const result = await invoke('measure_connection');
    if (result.error) $('#connection-description').textContent = 'Процесс активен, но внешний канал пока недоступен';
    await poll();
  } catch (error) { notify(error, true); }
  finally { probing = false; }
}
async function toggle() {
  if (busy) return;
  if (!connected && !$('#vless-key').value.trim()) { tab('settings'); $('#vless-key').focus(); notify('Войдите в KasperVPN или добавьте VLESS-ссылку.'); return; }
  busy = true;
  document.body.classList.add('busy');
  $('#power').disabled = true;
  $('#connect-label').disabled = true;
  $('#connection-title').textContent = connected ? 'Отключаемся…' : 'Открываем канал…';
  $('#connect-label').textContent = 'ПОДОЖДИТЕ…';
  try {
    if (connected) await invoke('disconnect_vpn');
    else {
      const settings = collect();
      await invoke('connect_vpn', { key: settings.key, splitSettings: settings });
      dirty = false;
      $$('.save-settings').forEach((button) => { button.textContent = 'Сохранить настройки'; });
    }
    lastError = '';
  } catch (error) { notify(error, true); }
  finally {
    busy = false;
    document.body.classList.remove('busy');
    $('#power').disabled = false;
    $('#connect-label').disabled = false;
    await poll();
    await probe();
    await refreshMtproto();
  }
}
$('#power').addEventListener('click', toggle);
$('#connect-label').addEventListener('click', toggle);
$('#copy-mtproto').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText($('#mtproto-link').value);
    notify('MTProto-ссылка скопирована — вставьте её в Telegram.');
  } catch (error) { notify(`Не удалось скопировать ссылку: ${error}`, true); }
});
(async () => {
  $('#power').disabled = true;
  $('#connect-label').disabled = true;
  try { populate(await invoke('load_settings')); await poll(); await loadAccount(); }
  catch (error) { notify(error, true); }
  finally { $('#power').disabled = false; $('#connect-label').disabled = false; }
  setInterval(poll, 1500);
  setInterval(probe, 15000);
})();
