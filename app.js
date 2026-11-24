/* TSG Biom Control — dashboard logic.
 *
 * Reads scan records and palm-bank profiles from the owner's own
 * TSG Biom API (GET /api/scans, GET /api/profiles, header x-read-key)
 * and renders them. The endpoint + read key live only in this
 * browser's localStorage. No sample or placeholder data anywhere:
 * every number on the page comes from the API response.
 *
 * The pure core (fetch, stats, filtering, HTML rendering) is kept
 * free of DOM access and exported as window.TsgBiomCore (and as a
 * Node module when loaded outside a browser) so the exact data path
 * shipped to the page can be exercised headlessly. */
(function () {
  'use strict';

  var DEFAULT_ENDPOINT = 'https://tsg-biom-api.vercel.app';
  var LS_ENDPOINT = 'tsgBiomControl.endpoint';
  var LS_READ_KEY = 'tsgBiomControl.readKey';

  var KIND_LABELS = {
    'enrol': 'Enrolment',
    'verify': 'Verify',
    'identify': 'Identify',
    'wallet-open': 'Wallet open',
    'money-auth': 'Money auth',
    'topup': 'Top-up',
    're-register': 'Re-register',
    'delete-all': 'Delete all',
    'field-test': 'Field test'
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
      profiles: profiles.length,
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
      var edccCount = Array.isArray(p.edccCodes) ? p.edccCodes.length : 0;
      var embCount = Array.isArray(p.neuralEmbeddings) ? p.neuralEmbeddings.length : 0;
      return '<article class="profile-card">' +
        '<h3>' + esc(p.name || 'Unnamed profile') + '</h3>' +
        '<div class="biom-id">' + esc(p.biomId || '') + '</div>' +
        '<dl class="profile-meta">' +
        '<div><dt>Hand</dt><dd>' + esc(handLabel(p.hand)) + '</dd></div>' +
        '<div><dt>Model</dt><dd>' + esc(p.neuralModel || '—') + '</dd></div>' +
        '<div><dt>EDCC templates</dt><dd>' + edccCount + '</dd></div>' +
        '<div><dt>PalmNet embeddings</dt><dd>' + embCount + '</dd></div>' +
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
      fetchJson(endpoint, readKey, '/api/profiles', fetchFn)
    ]).then(function (r) {
      return {
        scans: Array.isArray(r[0].scans) ? r[0].scans : [],
        profiles: Array.isArray(r[1].profiles) ? r[1].profiles : []
      };
    });
  }

  var Core = {
    DEFAULT_ENDPOINT: DEFAULT_ENDPOINT,
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

  function $(id) { return document.getElementById(id); }

  function storedCreds() {
    try {
      var endpoint = window.localStorage.getItem(LS_ENDPOINT);
      var key = window.localStorage.getItem(LS_READ_KEY);
      if (endpoint && key) return { endpoint: endpoint, readKey: key };
    } catch (e) { /* storage unavailable */ }
    return null;
  }

  function saveCreds(endpoint, readKey) {
    try {
      window.localStorage.setItem(LS_ENDPOINT, endpoint);
      window.localStorage.setItem(LS_READ_KEY, readKey);
    } catch (e) { /* storage unavailable */ }
  }

  function clearCreds() {
    try {
      window.localStorage.removeItem(LS_ENDPOINT);
      window.localStorage.removeItem(LS_READ_KEY);
    } catch (e) { /* storage unavailable */ }
  }

  function showSetup(message) {
    stopAutoRefresh();
    els.setupView.hidden = false;
    els.mainView.hidden = true;
    els.topbarActions.hidden = true;
    if (message) {
      els.setupError.textContent = message;
      els.setupError.hidden = false;
    } else {
      els.setupError.hidden = true;
    }
  }

  function showMain() {
    els.setupView.hidden = true;
    els.mainView.hidden = false;
    els.topbarActions.hidden = false;
    var creds = storedCreds();
    els.endpointChip.textContent = creds ? creds.endpoint : '';
  }

  function showError(err) {
    var creds = storedCreds();
    els.statusBanner.hidden = true;
    if (err && err.status === 401) {
      els.errorText.textContent = 'The read key was refused by the API (unauthorised). ' +
        'The key stored in this browser does not match the READ_KEY on the server.';
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
    var creds = storedCreds();
    if (!creds || state.loading) return Promise.resolve();
    state.loading = true;
    els.refreshBtn.disabled = true;
    els.errorBanner.hidden = true;
    els.statusBanner.hidden = false;
    els.statusText.textContent = 'Loading records…';
    return Core.loadAll(creds.endpoint, creds.readKey)
      .then(function (data) {
        state.scans = data.scans;
        state.profiles = data.profiles;
        els.statusBanner.hidden = true;
        renderAll();
      })
      .catch(function (err) {
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
    clearCreds();
    state.scans = [];
    state.profiles = [];
    els.readKeyInput.value = '';
    showSetup(null);
  }

  function init() {
    ['setupView', 'mainView', 'topbarActions', 'endpointChip', 'setupForm', 'endpointInput',
     'readKeyInput', 'setupError', 'connectBtn', 'errorBanner', 'errorText', 'reenterBtn',
     'statusBanner', 'statusText', 'statsGrid', 'profilesGrid', 'profilesEmpty',
     'kindFilter', 'resultFilter', 'searchInput', 'scanCountLine', 'scansBody',
     'scansEmpty', 'refreshBtn', 'disconnectBtn', 'autoRefreshToggle'
    ].forEach(function (id) { els[id] = $(id); });

    els.setupForm.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var endpoint = els.endpointInput.value.trim() || DEFAULT_ENDPOINT;
      var readKey = els.readKeyInput.value.trim();
      if (!readKey) return;
      els.connectBtn.disabled = true;
      els.setupError.hidden = true;
      Core.loadAll(endpoint, readKey)
        .then(function (data) {
          saveCreds(endpoint, readKey);
          state.scans = data.scans;
          state.profiles = data.profiles;
          showMain();
          renderAll();
        })
        .catch(function (err) {
          if (err && err.status === 401) {
            els.setupError.textContent = 'The read key was refused by the API (unauthorised). ' +
              'Check that you entered the READ_KEY set on the server, then try again.';
          } else if (err && err.status) {
            els.setupError.textContent = 'The API answered with an error (HTTP ' + err.status + '). Check the endpoint and try again.';
          } else {
            els.setupError.textContent = 'Could not reach the API at ' + endpoint + '. Check the address and your connection, then try again.';
          }
          els.setupError.hidden = false;
        })
        .then(function () { els.connectBtn.disabled = false; });
    });

    els.refreshBtn.addEventListener('click', refresh);
    els.disconnectBtn.addEventListener('click', disconnect);
    els.reenterBtn.addEventListener('click', disconnect);
    els.autoRefreshToggle.addEventListener('change', function () {
      if (els.autoRefreshToggle.checked) { startAutoRefresh(); refresh(); }
      else stopAutoRefresh();
    });
    ['kindFilter', 'resultFilter'].forEach(function (id) {
      els[id].addEventListener('change', renderAll);
    });
    els.searchInput.addEventListener('input', renderAll);

    var creds = storedCreds();
    if (creds) {
      els.endpointInput.value = creds.endpoint;
      showMain();
      refresh();
    } else {
      showSetup(null);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
