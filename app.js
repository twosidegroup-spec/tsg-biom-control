/* TSG Biom Control — dashboard logic.
 *
 * Reads scan records and palm-bank SUMMARIES from the owner's own
 * TSG Biom API (GET /api/scans, GET /api/profiles?summary=1,
 * header x-read-key) and renders them. Since v62 the dashboard
 * never downloads full template banks just to show counts: the
 * summary endpoint returns counts, bank versions, encryption
 * state, owner device and tombstone flags only — no template
 * strings cross the wire. No sample or placeholder data
 * anywhere: every number on the page comes from the API
 * response.
 *
 * Login (v63): password-only. The endpoint + read key are kept
 * in this browser SEALED — AES-GCM under a key derived from the
 * dashboard password with PBKDF2-SHA-256 (600,000 iterations) —
 * never in plain text at rest, and the password itself is never
 * stored anywhere: a correct password is simply one whose
 * derived key opens the seal (the GCM tag is the check). First
 * run asks for the read key once and seals it under the
 * password; every later visit asks only for the password, and
 * no API call is made before it unlocks. A browser that still
 * holds the pre-v63 plaintext key is migrated: set the password
 * once, the key is sealed, the plaintext is deleted.
 *
 * The pure core (fetch, stats, filtering, HTML rendering, and
 * the seal/unseal crypto) is kept free of DOM access and
 * exported as window.TsgBiomCore (and as a Node module when
 * loaded outside a browser) so the exact data path shipped to
 * the page can be exercised headlessly. */
(function () {
  'use strict';

  var DEFAULT_ENDPOINT = 'https://tsg-biom-api.vercel.app';
  var LS_ENDPOINT = 'tsgBiomControl.endpoint';
  var LS_READ_KEY = 'tsgBiomControl.readKey';
  var LS_SEALED = 'tsgBiomControl.sealed';

  var KIND_LABELS = {
    'enrol': 'Enrolment',
    'verify': 'Verify',
    'identify': 'Identify',
    'wallet-open': 'Wallet open',
    'money-auth': 'Money auth',
    'topup': 'Top-up',
    're-register': 'Re-register',
    'delete-all': 'Delete all',
    'field-test': 'Field test',
    'owner-unlock': 'Owner unlock'
  };

  /* ---------------- helpers ---------------- */

  function esc(v) {
    return String(v === null || v === undefined ? '' : v)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function fmtScore(v) {
    return typeof v === 'number' && Number.isFinite(v) ? v.toFixed(3) : '—';
  }

  var dhakaFmt = null;
  function fmtDhaka(ts) {
    if (typeof ts !== 'number' || !Number.isFinite(ts)) return '—';
    try {
      if (!dhakaFmt) {
        dhakaFmt = new Intl.DateTimeFormat('en-GB', {
          timeZone: 'Asia/Dhaka',
          day: '2-digit', month: 'short', year: 'numeric',
          hour: '2-digit', minute: '2-digit', second: '2-digit',
          hour12: false
        });
      }
      return dhakaFmt.format(new Date(ts));
    } catch (e) {
      return new Date(ts).toISOString();
    }
  }

  function kindLabel(kind) {
    return KIND_LABELS[kind] || (kind ? String(kind) : '—');
  }

  function handLabel(hand) {
    if (hand === 'left') return 'Left';
    if (hand === 'right') return 'Right';
    return '—';
  }

  /* 'verified' | 'denied' | 'other' from the free-text result the device recorded. */
  function classifyResult(result) {
    var r = String(result || '').toLowerCase();
    if (r.indexOf('verif') !== -1 || r === 'ok' || r.indexOf('accept') !== -1) return 'verified';
    if (r.indexOf('den') !== -1 || r.indexOf('reject') !== -1 || r.indexOf('fail') !== -1) return 'denied';
    return 'other';
  }

  function sortNewestFirst(scans) {
    return scans.slice().sort(function (a, b) { return (b.ts || 0) - (a.ts || 0); });
  }

  /* ---------------- stats ---------------- */

  function computeStats(scans, profiles) {
    var verified = 0, denied = 0, last = null;
    scans.forEach(function (s) {
      var c = classifyResult(s.result);
      if (c === 'verified') verified++;
      else if (c === 'denied') denied++;
      if (typeof s.ts === 'number' && (last === null || s.ts > last)) last = s.ts;
    });
    return {
      totalScans: scans.length,
      verified: verified,
      denied: denied,
      /* v62: tombstoned banks still arrive in the summary list
         (they render as Removed cards) but they are not enrolled
         profiles — the stat counts live banks only. */
      profiles: profiles.filter(function (p) { return !(p && p.deleted === true); }).length,
      lastScanTs: last
    };
  }

  /* ---------------- filtering ---------------- */

  function filterScans(scans, f) {
    f = f || {};
    var kind = f.kind || '';
    var result = f.result || '';
    var q = String(f.query || '').trim().toLowerCase();
    return sortNewestFirst(scans).filter(function (s) {
      if (kind && s.kind !== kind) return false;
      if (result && classifyResult(s.result) !== result) return false;
      if (q) {
        var hay = (String(s.profileName || '') + ' ' + String(s.biomId || '')).toLowerCase();
        if (hay.indexOf(q) === -1) return false;
      }
      return true;
    });
  }

  function kindsPresent(scans) {
    var seen = {}, out = [];
    scans.forEach(function (s) { if (s.kind && !seen[s.kind]) { seen[s.kind] = true; out.push(s.kind); } });
    return out.sort();
  }

  /* ---------------- rendering (HTML strings) ---------------- */

  function renderStatsHtml(stats) {
    function card(label, value, sub, small) {
      return '<div class="stat"><div class="stat-label">' + esc(label) + '</div>' +
        '<div class="stat-value' + (small ? ' small' : '') + '">' + esc(value) + '</div>' +
        (sub ? '<div class="stat-sub">' + esc(sub) + '</div>' : '') + '</div>';
    }
    return card('Total scans', stats.totalScans, 'records synced') +
      card('Verified', stats.verified, 'accepted scans') +
      card('Denied', stats.denied, 'refused scans') +
      card('Enrolled profiles', stats.profiles, 'palm banks synced') +
      card('Last scan', stats.lastScanTs === null ? '—' : fmtDhaka(stats.lastScanTs), 'Asia/Dhaka', true);
  }

  function renderProfilesHtml(profiles) {
    return profiles.map(function (p) {
      /* v62: profiles arrive as SUMMARIES (counts, not template
         arrays). The array-length fallbacks keep an older API
         response renderable, but the summary fields win. */
      var edccCount = typeof p.edccCount === 'number' ? p.edccCount
        : (Array.isArray(p.edccCodes) ? p.edccCodes.length : 0);
      var embCount = typeof p.neuralCount === 'number' ? p.neuralCount
        : (Array.isArray(p.neuralEmbeddings) ? p.neuralEmbeddings.length : 0);
      if (p.deleted === true) {
        return '<article class="profile-card profile-removed">' +
          '<h3>Removed</h3>' +
          '<div class="biom-id">' + esc(p.biomId || '') + '</div>' +
          '<dl class="profile-meta">' +
          '<div><dt>Status</dt><dd>Deleted (tombstone)</dd></div>' +
          '<div><dt>Removed</dt><dd>' + esc(fmtDhaka(p.deletedTs)) + '</dd></div>' +
          '<div><dt>Version</dt><dd>' + esc(typeof p.version === 'number' ? p.version : '—') + '</dd></div>' +
          '</dl></article>';
      }
      return '<article class="profile-card">' +
        '<h3>' + esc(p.name || 'Unnamed profile') + '</h3>' +
        '<div class="biom-id">' + esc(p.biomId || '') + '</div>' +
        '<dl class="profile-meta">' +
        '<div><dt>Hand</dt><dd>' + esc(handLabel(p.hand)) + '</dd></div>' +
        '<div><dt>Model</dt><dd>' + esc(p.neuralModel || '—') + '</dd></div>' +
        '<div><dt>EDCC templates</dt><dd>' + edccCount + '</dd></div>' +
        '<div><dt>PalmNet embeddings</dt><dd>' + embCount + '</dd></div>' +
        '<div><dt>Version</dt><dd>' + esc(typeof p.version === 'number' ? p.version : '—') + '</dd></div>' +
        '<div><dt>Encryption</dt><dd>' + esc(p.enc === 'v1' ? 'Sealed (enc v1)' : 'Encoded') + '</dd></div>' +
        '<div><dt>Owner device</dt><dd>' + esc(p.ownerDeviceId || '—') + '</dd></div>' +
        '<div><dt>Last updated</dt><dd>' + esc(fmtDhaka(p.updatedTs)) + '</dd></div>' +
        '</dl></article>';
    }).join('');
  }

  function resultBadgeHtml(result) {
    var c = classifyResult(result);
    var text = result ? String(result) : '—';
    return '<span class="badge badge-' + c + '">' + esc(text) + '</span>';
  }

  function renderScansRowsHtml(scans) {
    return scans.map(function (s) {
      var profileCell = '<span class="profile-name">' + esc(s.profileName || '—') + '</span>' +
        (s.biomId ? '<span class="profile-id">' + esc(s.biomId) + '</span>' : '');
      return '<tr>' +
        '<td data-label="Time" class="time">' + esc(fmtDhaka(s.ts)) + '</td>' +
        '<td data-label="Kind">' + esc(kindLabel(s.kind)) + '</td>' +
        '<td data-label="Profile">' + profileCell + '</td>' +
        '<td data-label="Hand">' + esc(handLabel(s.hand)) + '</td>' +
        '<td data-label="EDCC" class="num">' + esc(fmtScore(s.edccScore)) + '</td>' +
        '<td data-label="PalmNet" class="num">' + esc(fmtScore(s.palmnetScore)) + '</td>' +
        '<td data-label="Result">' + resultBadgeHtml(s.result) + '</td>' +
        '<td data-label="Device">' + esc(s.deviceLabel || '—') + '</td>' +
        '</tr>';
    }).join('');
  }

  function renderKindOptionsHtml(scans, selected) {
    var opts = ['<option value="">All kinds</option>'];
    kindsPresent(scans).forEach(function (k) {
      opts.push('<option value="' + esc(k) + '"' + (k === selected ? ' selected' : '') + '>' +
        esc(kindLabel(k)) + '</option>');
    });
    return opts.join('');
  }

  /* ---------------- API ---------------- */

  function apiError(status, message) {
    var e = new Error(message || ('HTTP ' + status));
    e.status = status;
    return e;
  }

  function fetchJson(endpoint, readKey, path, fetchFn) {
    var f = fetchFn || (typeof fetch !== 'undefined' ? fetch : null);
    if (!f) return Promise.reject(apiError(0, 'fetch is not available'));
    var base = String(endpoint || '').replace(/\/+$/, '');
    return f(base + path, {
      method: 'GET',
      headers: { 'x-read-key': readKey, 'Accept': 'application/json' }
    }).then(function (res) {
      if (res.status === 401) throw apiError(401, 'unauthorised');
      if (!res.ok) throw apiError(res.status, 'HTTP ' + res.status);
      return res.json();
    });
  }

  function loadAll(endpoint, readKey, fetchFn) {
    return Promise.all([
      fetchJson(endpoint, readKey, '/api/scans', fetchFn),
      /* v62 (Seat 1 Spec C5/D8/G5): summaries only — the full
         bank list is never fetched by this dashboard. */
      fetchJson(endpoint, readKey, '/api/profiles?summary=1', fetchFn)
    ]).then(function (r) {
      return {
        scans: Array.isArray(r[0].scans) ? r[0].scans : [],
        profiles: Array.isArray(r[1].profiles) ? r[1].profiles : []
      };
    });
  }

  /* ---------------- credential seal (v63) -----------------------
     AES-GCM-256 under a PBKDF2-SHA-256 key derived from the
     dashboard password (600,000 iterations, random 16-byte salt,
     fresh 12-byte IV per seal). The sealed record is plain JSON
     of base64 parts — it contains no readable credential, and
     the password is never stored: unsealing with a wrong
     password fails the GCM tag check and rejects. */

  var PBKDF2_ITERATIONS = 600000;

  function bytesToB64(bytes) {
    if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('base64');
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  function b64ToBytes(str) {
    if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(String(str), 'base64'));
    var bin = atob(String(str));
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function subtleCrypto() {
    return (typeof crypto !== 'undefined' && crypto.subtle) ? crypto.subtle : null;
  }

  function deriveSealKey(subtle, password, salt, iterations) {
    return subtle.importKey('raw', new TextEncoder().encode(String(password)), 'PBKDF2', false, ['deriveKey'])
      .then(function (base) {
        return subtle.deriveKey(
          { name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256' },
          base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
      });
  }

  function sealCredentials(password, creds) {
    var subtle = subtleCrypto();
    if (!subtle) return Promise.reject(new Error('WebCrypto is not available in this browser'));
    var salt = crypto.getRandomValues(new Uint8Array(16));
    var iv = crypto.getRandomValues(new Uint8Array(12));
    return deriveSealKey(subtle, password, salt, PBKDF2_ITERATIONS).then(function (key) {
      var payload = JSON.stringify({ endpoint: creds.endpoint, readKey: creds.readKey });
      return subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, new TextEncoder().encode(payload));
    }).then(function (ct) {
      return {
        v: 1, iter: PBKDF2_ITERATIONS,
        salt: bytesToB64(salt), iv: bytesToB64(iv), ct: bytesToB64(new Uint8Array(ct))
      };
    });
  }

  function unsealCredentials(password, sealed) {
    var subtle = subtleCrypto();
    if (!subtle) return Promise.reject(new Error('WebCrypto is not available in this browser'));
    if (!sealed || sealed.v !== 1 || !sealed.salt || !sealed.iv || !sealed.ct) {
      return Promise.reject(new Error('No sealed credential on this browser'));
    }
    return deriveSealKey(subtle, password, b64ToBytes(sealed.salt), sealed.iter || PBKDF2_ITERATIONS)
      .then(function (key) {
        return subtle.decrypt({ name: 'AES-GCM', iv: b64ToBytes(sealed.iv) }, key, b64ToBytes(sealed.ct));
      })
      .then(function (pt) {
        var obj = JSON.parse(new TextDecoder().decode(pt));
        if (!obj || !obj.readKey) throw new Error('Sealed credential is incomplete');
        return { endpoint: obj.endpoint || DEFAULT_ENDPOINT, readKey: obj.readKey };
      });
  }

  var Core = {
    DEFAULT_ENDPOINT: DEFAULT_ENDPOINT,
    PBKDF2_ITERATIONS: PBKDF2_ITERATIONS,
    sealCredentials: sealCredentials,
    unsealCredentials: unsealCredentials,
    esc: esc,
    fmtScore: fmtScore,
    fmtDhaka: fmtDhaka,
    kindLabel: kindLabel,
    handLabel: handLabel,
    classifyResult: classifyResult,
    computeStats: computeStats,
    filterScans: filterScans,
    kindsPresent: kindsPresent,
    renderStatsHtml: renderStatsHtml,
    renderProfilesHtml: renderProfilesHtml,
    renderScansRowsHtml: renderScansRowsHtml,
    renderKindOptionsHtml: renderKindOptionsHtml,
    fetchJson: fetchJson,
    loadAll: loadAll
  };

  if (typeof module !== 'undefined' && module.exports) module.exports = Core;
  if (typeof window !== 'undefined') window.TsgBiomCore = Core;

  /* ---------------- browser wiring ---------------- */

  if (typeof document === 'undefined' || typeof window === 'undefined') return;

  var els = {};
  var state = { scans: [], profiles: [], loading: false, timer: null };
  /* v63: the unsealed credentials live ONLY in this variable —
     memory, never storage. Locked means null, and refresh()
     does nothing while locked, so no API call can happen
     before the password unlocks the seal. */
  var sessionCreds = null;
  var setupMode = 'fresh'; // 'fresh' | 'migrate' (pre-v63 plaintext key found)

  function $(id) { return document.getElementById(id); }

  function storedSealed() {
    try {
      var raw = window.localStorage.getItem(LS_SEALED);
      if (!raw) return null;
      var obj = JSON.parse(raw);
      return obj && obj.v === 1 ? obj : null;
    } catch (e) { /* storage unavailable */ }
    return null;
  }

  function saveSealed(sealed) {
    try { window.localStorage.setItem(LS_SEALED, JSON.stringify(sealed)); } catch (e) { /* storage unavailable */ }
  }

  /* Pre-v63 browsers hold the key in plain text. It is read
     ONLY to migrate it into the seal, and deleted the moment
     the seal is written. Nothing new is ever written there. */
  function legacyCreds() {
    try {
      var endpoint = window.localStorage.getItem(LS_ENDPOINT);
      var key = window.localStorage.getItem(LS_READ_KEY);
      if (endpoint && key) return { endpoint: endpoint, readKey: key };
    } catch (e) { /* storage unavailable */ }
    return null;
  }

  function clearStored() {
    try {
      window.localStorage.removeItem(LS_SEALED);
      window.localStorage.removeItem(LS_ENDPOINT);
      window.localStorage.removeItem(LS_READ_KEY);
    } catch (e) { /* storage unavailable */ }
  }

  function showSetup(message, mode) {
    stopAutoRefresh();
    setupMode = mode || 'fresh';
    els.lockView.hidden = true;
    els.setupView.hidden = false;
    els.mainView.hidden = true;
    els.topbarActions.hidden = true;
    var migrate = setupMode === 'migrate';
    els.fieldEndpointWrap.hidden = migrate;
    els.fieldKeyWrap.hidden = migrate;
    /* hidden fields must not block the form's validation */
    els.endpointInput.required = !migrate;
    els.readKeyInput.required = !migrate;
    els.setupIntroFresh.hidden = migrate;
    els.setupIntroMigrate.hidden = !migrate;
    els.setupHeading.textContent = migrate ? 'Protect this browser with your password' : 'Connect to your TSG Biom API';
    els.connectBtn.textContent = migrate ? 'Seal the key and continue' : 'Connect';
    if (message) {
      els.setupError.textContent = message;
      els.setupError.hidden = false;
    } else {
      els.setupError.hidden = true;
    }
  }

  function showLock(message) {
    stopAutoRefresh();
    els.setupView.hidden = true;
    els.mainView.hidden = true;
    els.topbarActions.hidden = true;
    els.lockView.hidden = false;
    els.lockPasswordInput.value = '';
    if (message) {
      els.lockError.textContent = message;
      els.lockError.hidden = false;
    } else {
      els.lockError.hidden = true;
    }
  }

  function showMain() {
    els.setupView.hidden = true;
    els.lockView.hidden = true;
    els.mainView.hidden = false;
    els.topbarActions.hidden = false;
    els.endpointChip.textContent = sessionCreds ? sessionCreds.endpoint : '';
  }

  function showError(err) {
    var creds = sessionCreds;
    els.statusBanner.hidden = true;
    if (err && err.status === 401) {
      els.errorText.textContent = 'The read key was refused by the API (unauthorised). ' +
        'The key sealed in this browser does not match the READ_KEY on the server.';
      els.reenterBtn.hidden = false;
    } else if (err && err.status) {
      els.errorText.textContent = 'The API answered with an error (HTTP ' + err.status + '). ' +
        'Your existing records below are unchanged.';
      els.reenterBtn.hidden = true;
    } else {
      els.errorText.textContent = 'Could not reach the API' +
        (creds ? ' at ' + creds.endpoint : '') +
        '. Check the endpoint address and your connection, then refresh.';
      els.reenterBtn.hidden = true;
    }
    els.errorBanner.hidden = false;
  }

  function renderAll() {
    var stats = Core.computeStats(state.scans, state.profiles);
    els.statsGrid.innerHTML = Core.renderStatsHtml(stats);

    els.profilesGrid.innerHTML = Core.renderProfilesHtml(state.profiles);
    els.profilesEmpty.hidden = state.profiles.length !== 0;

    var currentKind = els.kindFilter.value;
    els.kindFilter.innerHTML = Core.renderKindOptionsHtml(state.scans, currentKind);
    if (currentKind && Core.kindsPresent(state.scans).indexOf(currentKind) !== -1) {
      els.kindFilter.value = currentKind;
    }

    var filtered = Core.filterScans(state.scans, {
      kind: els.kindFilter.value,
      result: els.resultFilter.value,
      query: els.searchInput.value
    });
    els.scansBody.innerHTML = Core.renderScansRowsHtml(filtered);
    els.scansEmpty.hidden = filtered.length !== 0;
    els.scanCountLine.textContent = state.scans.length === 0
      ? 'No scan records yet.'
      : 'Showing ' + filtered.length + ' of ' + state.scans.length + ' scan records, newest first.';
  }

  function refresh() {
    var creds = sessionCreds;
    if (!creds || state.loading) return Promise.resolve();
    state.loading = true;
    els.refreshBtn.disabled = true;
    els.errorBanner.hidden = true;
    els.statusBanner.hidden = false;
    els.statusText.textContent = 'Loading records…';
    /* v64 (Seat 1 L-1 / Seat 3 R-UX7): on a cold load (nothing
       rendered yet) the grids hold skeleton blocks while the fetch
       runs — never an empty frame and never the "no profiles" note
       mid-flight. renderAll replaces them wholesale on success; on
       failure they are cleared so the error banner stands alone. */
    if (!state.scans.length && !state.profiles.length) {
      els.statsGrid.innerHTML = '<div class="skelstat"><div class="skelbar w40"></div><div class="skelbar w65"></div></div>' +
        '<div class="skelstat"><div class="skelbar w40"></div><div class="skelbar w65"></div></div>' +
        '<div class="skelstat"><div class="skelbar w40"></div><div class="skelbar w65"></div></div>';
      els.profilesGrid.innerHTML = '<div class="skelcard"><div class="skelbar w65"></div><div class="skelbar w40"></div><div class="skelbar w85"></div></div>' +
        '<div class="skelcard"><div class="skelbar w65"></div><div class="skelbar w40"></div><div class="skelbar w85"></div></div>';
    }
    return Core.loadAll(creds.endpoint, creds.readKey)
      .then(function (data) {
        state.scans = data.scans;
        state.profiles = data.profiles;
        els.statusBanner.hidden = true;
        renderAll();
      })
      .catch(function (err) {
        /* v64: a failed cold load leaves no skeleton behind. */
        if (!state.scans.length && !state.profiles.length) {
          els.statsGrid.innerHTML = '';
          els.profilesGrid.innerHTML = '';
        }
        showError(err);
        if (err && err.status === 401) stopAutoRefresh();
      })
      .then(function () {
        state.loading = false;
        els.refreshBtn.disabled = false;
      });
  }

  function startAutoRefresh() {
    stopAutoRefresh();
    state.timer = window.setInterval(refresh, 30000);
  }

  function stopAutoRefresh() {
    if (state.timer !== null) {
      window.clearInterval(state.timer);
      state.timer = null;
    }
    if (els.autoRefreshToggle) els.autoRefreshToggle.checked = false;
  }

  function disconnect() {
    sessionCreds = null;
    clearStored();
    state.scans = [];
    state.profiles = [];
    els.readKeyInput.value = '';
    els.passwordInput.value = '';
    els.passwordConfirmInput.value = '';
    showSetup(null, 'fresh');
  }

  function lock() {
    sessionCreds = null;
    state.scans = [];
    state.profiles = [];
    showLock(null);
  }

  function init() {
    ['setupView', 'lockView', 'mainView', 'topbarActions', 'endpointChip', 'setupForm', 'endpointInput',
     'readKeyInput', 'passwordInput', 'passwordConfirmInput', 'setupError', 'connectBtn',
     'setupHeading', 'setupIntroFresh', 'setupIntroMigrate', 'fieldEndpointWrap', 'fieldKeyWrap',
     'lockForm', 'lockPasswordInput', 'lockError', 'unlockBtn', 'lockResetBtn',
     'errorBanner', 'errorText', 'reenterBtn',
     'statusBanner', 'statusText', 'statsGrid', 'profilesGrid', 'profilesEmpty',
     'kindFilter', 'resultFilter', 'searchInput', 'scanCountLine', 'scansBody',
     'scansEmpty', 'refreshBtn', 'disconnectBtn', 'lockBtn', 'autoRefreshToggle'
    ].forEach(function (id) { els[id] = $(id); });

    els.setupForm.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var password = els.passwordInput.value;
      var confirm = els.passwordConfirmInput.value;
      if (!password) {
        els.setupError.textContent = 'Set the dashboard password — it seals the read key on this browser.';
        els.setupError.hidden = false;
        return;
      }
      /* v64 (Seat 2 M-6): a minimum length at SETUP and MIGRATION
         only — the seal previously accepted any non-empty string,
         including a one-character password over the read key. The
         unlock path is deliberately NOT length-checked: an existing
         seal must always open with the password it was made with. */
      if (password.length < 8) {
        els.setupError.textContent = 'Use at least 8 characters for the dashboard password — it is the only thing protecting the sealed read key on this browser.';
        els.setupError.hidden = false;
        return;
      }
      if (password !== confirm) {
        els.setupError.textContent = 'The two passwords do not match. Type the same password in both boxes.';
        els.setupError.hidden = false;
        return;
      }
      els.connectBtn.disabled = true;
      els.setupError.hidden = true;

      var finishSetup = function (creds) {
        return Core.sealCredentials(password, creds).then(function (sealed) {
          saveSealed(sealed);
          /* the plaintext legacy entries (if any) die the
             moment the seal exists */
          try {
            window.localStorage.removeItem(LS_ENDPOINT);
            window.localStorage.removeItem(LS_READ_KEY);
          } catch (e) { /* storage unavailable */ }
          sessionCreds = creds;
          els.passwordInput.value = '';
          els.passwordConfirmInput.value = '';
          showMain();
        });
      };

      if (setupMode === 'migrate') {
        var legacy = legacyCreds();
        if (!legacy) { showSetup(null, 'fresh'); els.connectBtn.disabled = false; return; }
        finishSetup(legacy)
          .then(function () { refresh(); })
          .catch(function () {
            els.setupError.textContent = 'Could not seal the key in this browser. Try again.';
            els.setupError.hidden = false;
          })
          .then(function () { els.connectBtn.disabled = false; });
        return;
      }

      var endpoint = els.endpointInput.value.trim() || DEFAULT_ENDPOINT;
      var readKey = els.readKeyInput.value.trim();
      if (!readKey) { els.connectBtn.disabled = false; return; }
      Core.loadAll(endpoint, readKey)
        .then(function (data) {
          state.scans = data.scans;
          state.profiles = data.profiles;
          return finishSetup({ endpoint: endpoint, readKey: readKey });
        })
        .then(function () { renderAll(); })
        .catch(function (err) {
          if (err && err.status === 401) {
            els.setupError.textContent = 'The read key was refused by the API (unauthorised). ' +
              'Check that you entered the READ_KEY set on the server, then try again.';
          } else if (err && err.status) {
            els.setupError.textContent = 'The API answered with an error (HTTP ' + err.status + '). Check the endpoint and try again.';
          } else if (err && err.message && err.message.indexOf('Seal') !== -1) {
            els.setupError.textContent = 'Could not seal the key in this browser. Try again.';
          } else {
            els.setupError.textContent = 'Could not reach the API at ' + endpoint + '. Check the address and your connection, then try again.';
          }
          els.setupError.hidden = false;
        })
        .then(function () { els.connectBtn.disabled = false; });
    });

    els.lockForm.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var sealed = storedSealed();
      if (!sealed) { showSetup(null, 'fresh'); return; }
      els.unlockBtn.disabled = true;
      els.lockError.hidden = true;
      Core.unsealCredentials(els.lockPasswordInput.value, sealed)
        .then(function (creds) {
          sessionCreds = creds;
          showMain();
          refresh();
        })
        .catch(function () {
          /* a wrong password fails the seal's integrity check —
             the dashboard stays locked and nothing was fetched */
          els.lockError.textContent = 'That password did not unlock this dashboard. Check it and try again.';
          els.lockError.hidden = false;
        })
        .then(function () { els.unlockBtn.disabled = false; });
    });

    var resetArmed = false;
    els.lockResetBtn.addEventListener('click', function () {
      if (!resetArmed) {
        resetArmed = true;
        els.lockResetBtn.textContent = 'Tap again to forget the sealed key on this browser';
        window.setTimeout(function () {
          resetArmed = false;
          els.lockResetBtn.textContent = 'Forget the sealed key on this browser';
        }, 4000);
        return;
      }
      resetArmed = false;
      els.lockResetBtn.textContent = 'Forget the sealed key on this browser';
      sessionCreds = null;
      clearStored();
      showSetup(null, 'fresh');
    });

    els.refreshBtn.addEventListener('click', refresh);
    els.disconnectBtn.addEventListener('click', disconnect);
    els.lockBtn.addEventListener('click', lock);
    els.reenterBtn.addEventListener('click', disconnect);
    els.autoRefreshToggle.addEventListener('change', function () {
      if (els.autoRefreshToggle.checked) { startAutoRefresh(); refresh(); }
      else stopAutoRefresh();
    });
    ['kindFilter', 'resultFilter'].forEach(function (id) {
      els[id].addEventListener('change', renderAll);
    });
    els.searchInput.addEventListener('input', renderAll);

    /* v63 entry rule: a sealed browser goes to the LOCK screen
       and fetches nothing until the password unlocks it; a
       pre-v63 plaintext browser goes to the one-time migration;
       a new browser goes to first-run setup. */
    if (storedSealed()) {
      showLock(null);
    } else if (legacyCreds()) {
      showSetup(null, 'migrate');
    } else {
      showSetup(null, 'fresh');
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
