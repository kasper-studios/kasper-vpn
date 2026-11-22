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
function updateSniBadge(sni) {
  const el = $('#sni-label');
  if (!el) return;
  if (!sni || sni === 'auto' || sni === 'gateway.icloud.com') {
    el.textContent = '🍏 ICLOUD';
  } else if (sni === 'www.samsung.com') {
    el.textContent = '📱 SAMSUNG';
  } else if (sni === 'www.microsoft.com') {
    el.textContent = '🪟 MICROSOFT';
  } else {
    el.textContent = `⚡ ${sni.slice(0, 15).toUpperCase()}`;
  }
}
function collect() {
  const sniSelected = $('input[name="sni"]:checked')?.value || 'auto';
  const customSni = $('#custom-sni')?.value.trim();
  const sni = sniSelected === 'custom' ? (customSni || 'gateway.icloud.com') : sniSelected;
  const port = $('input[name="port"]:checked')?.value || 'auto';
  return {
    ...(settingsCache || {}),
    key: $('#vless-key').value.trim(),
    applications: $$('input[name="application"]:checked').map((input) => input.value),
    domains: $('#domains').value,
    mode: $('input[name="mode"]:checked').value,
    singBoxPath: $('#sing-box-path').value.trim() || 'sing-box',
    mtprotoPort: Number($('#mtproto-port').value) || (settingsCache?.mtprotoPort ?? 17893),
    mtprotoSecret: settingsCache?.mtprotoSecret || '',
    sni,
    port,
  };
}
function updateAppCount() {
  const count = $$('input[name="application"]:checked').length;
  const el = $('#app-count');
  if (el) el.textContent = `${count} ВЫБРАНО`;
}
let installedAppsCache = [];
function renderApps(apps, selectedApps) {
  installedAppsCache = apps || [];
  const container = $('#app-list');
  if (!container) return;
  const query = ($('#app-search')?.value || '').toLowerCase().trim();
  const filtered = installedAppsCache.filter((app) => {
    if (!query) return true;
    return app.name.toLowerCase().includes(query) || app.exec.toLowerCase().includes(query);
  });
  container.innerHTML = filtered.map((app) => {
    const isChecked = selectedApps.includes(app.id) || selectedApps.includes(app.exec);
    const icon = app.id === 'discord' ? '◈' : app.id === 'spotify' ? '≋' : app.id === 'steam' ? '◉' : app.id === 'browser' ? '◎' : '⬡';
    const iconClass = ['discord', 'spotify', 'steam', 'browser'].includes(app.id) ? app.id : '';
    return `
      <label class="app-row" data-name="${app.name.toLowerCase()}" data-exec="${app.exec.toLowerCase()}">
        <span class="app-icon ${iconClass}">${icon}</span>
        <span><b>${app.name}</b><small>${app.exec}</small></span>
        <input type="checkbox" name="application" value="${app.id}" ${isChecked ? 'checked' : ''}>
        <span class="switch" aria-hidden="true"></span>
      </label>
    `;
  }).join('');
  $$('#app-list input[name="application"]').forEach((input) => {
    input.addEventListener('change', updateAppCount);
  });
  updateAppCount();
}
async function loadInstalledApps(selectedApps) {
  try {
    const apps = await invoke('list_installed_applications');
    renderApps(apps, selectedApps || (settingsCache?.applications || []));
  } catch (e) {
    console.error('Failed to list installed apps:', e);
  }
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
  const sni = settings.sni || 'auto';
  const knownSni = ['auto', 'gateway.icloud.com', 'www.samsung.com', 'www.microsoft.com'];
  if (knownSni.includes(sni)) {
    $$('input[name="sni"]').forEach((input) => { input.checked = input.value === sni; });
    const cGroup = $('#custom-sni-group');
    if (cGroup) cGroup.hidden = true;
  } else {
    $$('input[name="sni"]').forEach((input) => { input.checked = input.value === 'custom'; });
    const cInput = $('#custom-sni');
    if (cInput) cInput.value = sni;
    const cGroup = $('#custom-sni-group');
    if (cGroup) cGroup.hidden = false;
  }
  const port = settings.port || 'auto';
  $$('input[name="port"]').forEach((input) => { input.checked = input.value === port; });
  updateSniBadge(sni);
  loadInstalledApps(settings.applications || []);
  countDomains();
  refreshMtproto();
  refreshSingBoxStatus();
}
async function refreshSingBoxStatus() {
  try {
    const status = await invoke('get_sing_box_status');
    const titleEl = $('#sing-box-status-title');
    const pathEl = $('#sing-box-status-path');
    const btn = $('#install-sing-box-btn');
    if (!titleEl) return;
    if (status.installed) {
      titleEl.innerHTML = `🟢 <b>${status.version || 'sing-box установлен'}</b>`;
      pathEl.textContent = status.path;
      btn.hidden = true;
    } else {
      titleEl.innerHTML = `⚠️ <b>Движок sing-box не найден</b>`;
      pathEl.textContent = 'Будет установлен автоматически при подключении или по кнопке справа';
      btn.hidden = false;
      btn.disabled = false;
      btn.textContent = 'Установить автоматически';
    }
  } catch (e) {
    console.error('Failed to get sing-box status:', e);
  }
}
async function refreshMtproto() {
  try {
    const link = await invoke('mtproto_link');
    $('#mtproto-link').value = link.link || '';
    $('#copy-mtproto').disabled = !link.link;
    if (link.running) {
      $('#mtproto-status').innerHTML = '🟢 <b>MTProto-сервер активен.</b> Добавьте прокси в Telegram по ссылке выше или нажмите «Скопировать».';
    } else {
      $('#mtproto-status').innerHTML = '⚪ <b>Сервер не запущен.</b> Если хотите пустить через VPN <i>только Telegram</i>: выберите в блоке «Режим сети» режим «Telegram · MTProto-прокси» и нажмите «ПОДКЛЮЧИТЬ» на главной.<br><small class="muted">Если вам нужен обычный VPN для всей системы или TUN — этот блок настраивать не нужно.</small>';
    }
  } catch (_) { /* ignore */ }
}
async function save() {
  const buttons = $$('.save-settings');
  buttons.forEach((button) => { button.disabled = true; });
  try {
    await invoke('save_settings', { settings: collect() });
    dirty = false;
    buttons.forEach((button) => { button.textContent = 'Сохранить настройки'; });
    notify(connected ? 'Сохранено. Переподключитесь для применения изменений.' : 'Настройки сохранены на устройстве.');
    refreshQuota();
  } catch (error) { notify(error, true); }
  finally { buttons.forEach((button) => { button.disabled = false; }); }
}
$$('.save-settings').forEach((button) => button.addEventListener('click', save));
$$('input, textarea').forEach((input) => input.addEventListener('input', () => {
  dirty = true;
  $$('.save-settings').forEach((button) => { button.textContent = 'Сохранить изменения •'; });
  countDomains();
}));
$$('input[name="sni"]').forEach((input) => {
  input.addEventListener('change', () => {
    const isCustom = input.value === 'custom';
    const cGroup = $('#custom-sni-group');
    if (cGroup) cGroup.hidden = !isCustom;
    updateSniBadge(isCustom ? ($('#custom-sni')?.value || 'CUSTOM') : input.value);
  });
});
$('#custom-sni')?.addEventListener('input', () => {
  updateSniBadge($('#custom-sni')?.value || 'CUSTOM');
});
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
  const units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) { amount /= 1024; unit++; }
  return `${amount.toFixed(unit >= 3 ? 2 : (unit ? 1 : 0))} ${units[unit]}`;
}
async function refreshQuota() {
  try {
    const quota = await invoke('get_account_traffic');
    if (quota) {
      if (quota.isAdmin || Number(quota.totalGb) > 100000) {
        $('#quota-used').replaceChildren(document.createTextNode(`${quota.usedGb} `));
        const em = document.createElement('em'); em.textContent = 'ГБ'; $('#quota-used').append(em);
        $('#quota-details').textContent = `Безлимит · ${quota.username || 'Создатель'}`;
      } else if (Number(quota.totalGb) === 0) {
        $('#quota-used').replaceChildren(document.createTextNode('0 '));
        const em = document.createElement('em'); em.textContent = 'ГБ'; $('#quota-used').append(em);
        $('#quota-details').textContent = 'Подписка не оплачена';
      } else {
        $('#quota-used').replaceChildren(document.createTextNode(`${quota.usedGb} / ${quota.totalGb} `));
        const em = document.createElement('em'); em.textContent = 'ГБ'; $('#quota-used').append(em);
        $('#quota-details').textContent = `${quota.percentage}% использовано · ${quota.username}`;
      }
      if ($('#account-name')) $('#account-name').textContent = quota.username;
      if ($('#account-usage')) $('#account-usage').textContent = `${quota.usedGb} / ${quota.totalGb} ГБ · ${quota.percentage}%`;
    }
  } catch (_) {}
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
$('#install-sing-box-btn')?.addEventListener('click', async () => {
  const btn = $('#install-sing-box-btn');
  const titleEl = $('#sing-box-status-title');
  btn.disabled = true;
  btn.textContent = 'Загрузка...';
  if (titleEl) titleEl.innerHTML = '⏳ <b>Скачивание и настройка sing-box...</b>';
  try {
    await invoke('install_sing_box');
    notify('Движок sing-box успешно установлен!');
  } catch (e) {
    notify(`Ошибка установки sing-box: ${e}`, true);
  } finally {
    await refreshSingBoxStatus();
  }
});
$('#app-search')?.addEventListener('input', () => {
  const selected = $$('#app-list input[name="application"]:checked').map((i) => i.value);
  renderApps(installedAppsCache, selected);
});
(async () => {
  $('#power').disabled = true;
  $('#connect-label').disabled = true;
  try { populate(await invoke('load_settings')); await poll(); await loadAccount(); await refreshQuota(); }
  catch (error) { notify(error, true); }
  finally { $('#power').disabled = false; $('#connect-label').disabled = false; }
  setInterval(poll, 1500);
  setInterval(probe, 15000);
  setInterval(refreshQuota, 15000);
})();
