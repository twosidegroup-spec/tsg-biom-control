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
 * v78: the connection setup no longer fronts the dashboard. It
 * lives in a Settings page (Connection section: endpoint, read
 * key, and the new ADMIN key — all sealed under the same
 * password) reached from a quiet first-run notice when no seal
 * exists, and from the sidebar once unlocked. The front door is
 * the password-only lock whenever a seal exists. The person
 * view gains the server-stamped network capture, the palm as a
 * sealed-bank fingerprint (code, never an image — none exists),
 * the wallet ledger mirror, and Block/Unblock control backed
 * by the API's admin endpoints.
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

  /* v78: compact timestamp for narrow surfaces (the dossier's
     tables) — day + time to the minute, no year/seconds. */
  var dhakaShortFmt = null;
  function fmtDhakaShort(ts) {
    if (typeof ts !== 'number' || !Number.isFinite(ts)) return '—';
    try {
      if (!dhakaShortFmt) {
        dhakaShortFmt = new Intl.DateTimeFormat('en-GB', {
          timeZone: 'Asia/Dhaka',
          day: '2-digit', month: 'short',
          hour: '2-digit', minute: '2-digit', hour12: false
        });
      }
      return dhakaShortFmt.format(new Date(ts));
    } catch (e) {
      return fmtDhaka(ts);
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

  function computeStats(scans, profiles, research) {
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
      lastScanTs: last,
      /* v81: the research-frame count (simulation mode), when
         the API reported it; null keeps the card hidden. */
      research: research || null
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
    function card(label, value, sub, small, tone) {
      return '<div class="stat' + (tone ? ' tone-' + tone : '') + '"><div class="stat-label">' + esc(label) + '</div>' +
        '<div class="stat-value' + (small ? ' small' : '') + '">' + esc(value) + '</div>' +
        (sub ? '<div class="stat-sub">' + esc(sub) + '</div>' : '') + '</div>';
    }
    return card('Total scans', stats.totalScans, 'records synced') +
      card('Verified', stats.verified, 'accepted scans', false, 'ok') +
      card('Denied', stats.denied, 'refused scans', false, 'bad') +
      card('Enrolled profiles', stats.profiles, 'palm banks synced') +
      card('Last scan', stats.lastScanTs === null ? '—' : fmtDhaka(stats.lastScanTs), 'Asia/Dhaka', true) +
      /* v81: simulation/research mode — frames received for the
         detector research store, counted by the API's read-key
         research route. Shown only when the API reported it. */
      (stats.research ? card('Research frames', stats.research.frames, stats.research.bundles + ' bundles received · simulation mode') : '');
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
        '<td data-label="Duration">' + durationHtml(s) + '</td>' +
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


  /* ---------------- v66: banks table, drawer, overview panels ---------------- */

  function profileCounts(p) {
    return {
      edcc: typeof p.edccCount === 'number' ? p.edccCount
        : (Array.isArray(p.edccCodes) ? p.edccCodes.length : 0),
      emb: typeof p.neuralCount === 'number' ? p.neuralCount
        : (Array.isArray(p.neuralEmbeddings) ? p.neuralEmbeddings.length : 0)
    };
  }

  function sortProfiles(profiles, key, dir) {
    var d = dir === -1 ? -1 : 1;
    return profiles.slice().sort(function (a, b) {
      var av, bv;
      if (key === 'edccCount') { av = profileCounts(a).edcc; bv = profileCounts(b).edcc; }
      else if (key === 'neuralCount') { av = profileCounts(a).emb; bv = profileCounts(b).emb; }
      else if (key === 'status') { av = a.deleted === true ? 1 : 0; bv = b.deleted === true ? 1 : 0; }
      else if (key === 'version') { av = typeof a.version === 'number' ? a.version : -1; bv = typeof b.version === 'number' ? b.version : -1; }
      else { av = String(a[key] || '').toLowerCase(); bv = String(b[key] || '').toLowerCase(); }
      if (av < bv) return -1 * d;
      if (av > bv) return 1 * d;
      return 0;
    });
  }

  function renderBanksRowsHtml(profiles) {
    return profiles.map(function (p) {
      var c = profileCounts(p);
      var status = p.deleted === true
        ? '<span class="badge badge-denied">Removed</span>'
        : '<span class="badge badge-verified">Live</span>' +
          /* v78: a blocked person is flagged wherever their bank is listed */
          (p.blocked === true ? ' <span class="badge badge-denied">Blocked</span>' : '');
      return '<tr data-biom-id="' + esc(p.biomId || '') + '">' +
        '<td data-label="Biom ID">' + esc(p.biomId || '') + '</td>' +
        '<td data-label="Name"><span class="profile-name">' + esc(p.deleted === true ? 'Removed' : (p.name || 'Unnamed profile')) + '</span></td>' +
        '<td data-label="Hand">' + esc(handLabel(p.hand)) + '</td>' +
        '<td data-label="EDCC templates" class="num">' + c.edcc + '</td>' +
        '<td data-label="PalmNet templates" class="num">' + c.emb + '</td>' +
        '<td data-label="Version" class="num">' + esc(typeof p.version === 'number' ? p.version : '—') + '</td>' +
        '<td data-label="Status">' + status + '</td>' +
        '</tr>';
    }).join('');
  }

  /* The drawer shows the full SUMMARY record for one bank — the
     same fields the profile card renders. Summary data only. */
  /* v74: scan durations (Chairman's bar: a scan must complete
     in under two seconds). fmtDuration renders the real measured
     duration the device stamped on the record; a record without
     one (older app versions, or a scan whose timing could not be
     measured) shows Unmeasured — never an estimate. The flag is
     decided on the raw milliseconds, not the rounded display,
     so a 2,049 ms scan shows "2.0s" AND its Over 2s flag. */
  function fmtDuration(ms) {
    if (typeof ms !== 'number' || !isFinite(ms) || ms < 0) return 'Unmeasured';
    return (ms / 1000).toFixed(1) + 's';
  }
  function isSlowScan(s) {
    return !!s && typeof s.durationMs === 'number' && isFinite(s.durationMs) && s.durationMs > 2000;
  }
  function durationHtml(s) {
    var slow = isSlowScan(s);
    return '<span class="duration' + (slow ? ' duration-slow' : '') + '">' + esc(fmtDuration(s ? s.durationMs : null)) + '</span>' +
      (slow ? ' <span class="badge badge-denied">Over 2s</span>' : '');
  }

  function renderBankDetailHtml(p, scans) {
    if (!p) return '';
    var html = renderProfilesHtml([p]);
    /* v74: the registration record — name, phone, palm
       registered — followed by this person's scan history with
       durations (registration, strengthening and payment/send
       scans included: every synced scan carrying their Biom ID). */
    var counts = profileCounts(p);
    var palmLine;
    if (p.deleted === true) palmLine = 'Palm bank removed';
    else if (counts.edcc + counts.emb > 0) palmLine = handLabel(p.hand) + ' palm registered — ' + counts.edcc + ' EDCC template' + (counts.edcc === 1 ? '' : 's') + ', ' + counts.emb + ' PalmNet embedding' + (counts.emb === 1 ? '' : 's');
    else palmLine = 'No palm registered';
    html += '<article class="profile-card detail-card">' +
      '<h3>Registration record</h3>' +
      '<dl class="profile-meta">' +
      '<div><dt>Name</dt><dd>' + esc(p.name || '—') + '</dd></div>' +
      '<div><dt>Phone</dt><dd>' + esc(p.phone || '—') + '</dd></div>' +
      '<div><dt>Palm</dt><dd>' + esc(palmLine) + '</dd></div>' +
      '</dl></article>';
    var mine = sortNewestFirst((scans || []).filter(function (s) { return !!s && !!s.biomId && s.biomId === p.biomId; }));
    html += '<article class="profile-card detail-card">' +
      '<h3>Scan history</h3>' +
      (mine.length
        ? '<div class="table-wrap table-wrap-plain drawer-scroll"><table class="scans-table mini-table"><thead><tr>' +
          '<th scope="col">Time (Dhaka)</th><th scope="col">Kind</th><th scope="col">Result</th><th scope="col">Duration</th>' +
          '</tr></thead><tbody>' +
          mine.slice(0, 50).map(function (s) {
            return '<tr>' +
              '<td class="time">' + esc(fmtDhakaShort(s.ts)) + '</td>' +
              '<td>' + esc(kindLabel(s.kind)) + '</td>' +
              '<td>' + resultBadgeHtml(s.result) + '</td>' +
              '<td>' + durationHtml(s) + '</td>' +
              '</tr>';
          }).join('') +
          '</tbody></table></div>'
        : '<p class="empty-note">No scans recorded for this person yet.</p>') +
      '</article>';
    return html;
  }

  function renderRecentScansRowsHtml(scans) {
    var latest = sortNewestFirst(scans).slice(0, 8);
    return latest.map(function (s) {
      var profileCell = '<span class="profile-name">' + esc(s.profileName || '—') + '</span>' +
        (s.biomId ? '<span class="profile-id">' + esc(s.biomId) + '</span>' : '');
      return '<tr>' +
        '<td data-label="Time" class="time">' + esc(fmtDhaka(s.ts)) + '</td>' +
        '<td data-label="Profile">' + profileCell + '</td>' +
        '<td data-label="Result">' + resultBadgeHtml(s.result) + '</td>' +
        '</tr>';
    }).join('');
  }

  function renderVaultHealthHtml(profiles) {
    var removed = 0, sealed = 0, last = null;
    profiles.forEach(function (p) {
      if (p && p.deleted === true) removed++;
      if (p && p.enc === 'v1') sealed++;
      if (p && typeof p.updatedTs === 'number' && (last === null || p.updatedTs > last)) last = p.updatedTs;
    });
    return '<dl class="vault-list">' +
      '<div><dt>Palm banks</dt><dd>' + profiles.length + '</dd></div>' +
      '<div><dt>Removed (tombstones)</dt><dd>' + removed + '</dd></div>' +
      '<div><dt>Encryption</dt><dd>' + sealed + ' of ' + profiles.length + ' sealed (enc v1)</dd></div>' +
      '<div><dt>Sync status</dt><dd>' + (profiles.length ? 'Summaries synced from your API' : 'Nothing synced yet') + '</dd></div>' +
      '<div><dt>Last bank update</dt><dd>' + esc(last === null ? '—' : fmtDhaka(last)) + '</dd></div>' +
      '</dl>';
  }

  /* v80 (Gap 1): the cross-match line of a scan card — the top
     OTHER identity a denied scan's palm scored close to, per
     scoring system. Present only on records the app sent with
     cross-match evidence (an in-band near-match); ordinary
     records render exactly as before. */
  function crossMatchLine(s) {
    var parts = [];
    if (s.crossEdccId) parts.push(esc(s.crossEdccId) + ' · EDCC ' + esc(fmtScore(s.crossEdccScore)));
    if (s.crossNeuralId && s.crossNeuralId !== s.crossEdccId) parts.push(esc(s.crossNeuralId) + ' · PalmNet ' + esc(fmtScore(s.crossNeuralScore)));
    else if (s.crossNeuralId) parts.push('PalmNet ' + esc(fmtScore(s.crossNeuralScore)));
    return parts.join(' · ');
  }

  function renderScanCardsHtml(scans) {
    var sorted = sortNewestFirst(scans);
    var out = '', day = null;
    sorted.forEach(function (s) {
      var full = fmtDhaka(s.ts);
      var d = full.indexOf(',') !== -1 ? full.slice(0, full.indexOf(',')) : full;
      if (d !== day) { day = d; out += '<h3 class="scan-day">' + esc(d) + '</h3>'; }
      out += '<article class="scan-card">' +
        '<div>' + resultBadgeHtml(s.result) + '</div>' +
        '<div class="scan-card-row"><span class="k">Profile</span><span><span class="profile-name">' + esc(s.profileName || '—') + '</span>' +
        (s.biomId ? '<span class="profile-id">' + esc(s.biomId) + '</span>' : '') + '</span></div>' +
        '<div class="scan-card-row"><span class="k">Kind</span><span>' + esc(kindLabel(s.kind)) + '</span></div>' +
        '<div class="scan-card-row"><span class="k">Hand</span><span>' + esc(handLabel(s.hand)) + '</span></div>' +
        '<div class="scan-card-row"><span class="k">EDCC</span><span class="num">' + esc(fmtScore(s.edccScore)) + '</span></div>' +
        '<div class="scan-card-row"><span class="k">PalmNet</span><span class="num">' + esc(fmtScore(s.palmnetScore)) + '</span></div>' +
        ((s.crossEdccId || s.crossNeuralId)
          ? '<div class="scan-card-row"><span class="k">Closest other palm</span><span>' + crossMatchLine(s) + '</span></div>'
          : '') +
        '<div class="scan-card-row"><span class="k">Duration</span><span>' + durationHtml(s) + '</span></div>' +
        '<div class="scan-card-row"><span class="k">Time</span><span class="time">' + esc(full) + '</span></div>' +
        '<div class="scan-card-row"><span class="k">Device</span><span>' + esc(s.deviceLabel || '—') + '</span></div>' +
        '</article>';
    });
    return out;
  }

  /* ---------------- v78: person control view ----------------
     Network capture, the palm as an encrypted CODE, and the
     wallet ledger. Everything renders from the FULL summary the
     API serves only to the read key (v78): regIp/lastIp + geo,
     bankFingerprint + template sizes, the wallet mirror and the
     Biom Pay records. A summary from an older API (or a person
     whose phone has not synced on the v78 build yet) simply
     lacks those fields — the cards then say so plainly instead
     of inventing values. There is no palm image anywhere in
     this system; nothing image-like is ever rendered. */

  function fmtMoney(v) {
    if (typeof v !== 'number' || !Number.isFinite(v)) return '—';
    return 'BDT ' + v.toLocaleString('en-IN', { maximumFractionDigits: 2 });
  }

  /* '203.0.113.7 · Dhaka, BD' — any missing part drops out;
     nothing captured at all reads 'Not captured'. */
  function netLine(ip, country, city) {
    var place = [city, country].filter(function (x) { return !!x; }).join(', ');
    var parts = [];
    if (ip) parts.push(String(ip));
    if (place) parts.push(place);
    return parts.length ? parts.join(' · ') : 'Not captured';
  }

  /* The latest network sighting for a person: the profile's own
     last-write stamp vs the newest scan record carrying an IP —
     whichever is newer wins. */
  function latestNet(p, scans) {
    var best = null;
    if (p && p.lastIp) best = { ip: p.lastIp, country: p.lastGeoCountry || '', city: p.lastGeoCity || '', ts: typeof p.updatedTs === 'number' ? p.updatedTs : 0 };
    (scans || []).forEach(function (s) {
      if (!s || s.biomId !== (p && p.biomId) || !s.ip) return;
      if (!best || (s.ts || 0) >= best.ts) {
        best = { ip: s.ip, country: s.geoCountry || '', city: s.geoCity || '', ts: s.ts || 0 };
      }
    });
    return best;
  }

  function walletTotals(p) {
    var w = (p && p.wallet) || null;
    var t = { balance: w && typeof w.balance === 'number' ? w.balance : null, added: 0, sent: 0, received: 0, paid: 0 };
    if (w && Array.isArray(w.statement)) {
      w.statement.forEach(function (e) {
        if (!e || typeof e.amount !== 'number') return;
        if (e.kind === 'add') t.added += e.amount;
        else if (e.kind === 'send') t.sent += e.amount;
        else if (e.kind === 'receive') t.received += e.amount;
      });
    }
    if (p && Array.isArray(p.pays)) {
      p.pays.forEach(function (x) {
        if (x && typeof x.amount === 'number' && (!x.status || x.status === 'Completed')) t.paid += x.amount;
      });
    }
    return t;
  }

  function renderPersonControlHtml(p, scans) {
    if (!p || p.deleted === true) return '';
    var html = '';

    /* --- network: registration + latest seen --- */
    var latest = latestNet(p, scans);
    html += '<article class="profile-card detail-card">' +
      '<h3>Network</h3>' +
      '<dl class="profile-meta">' +
      '<div><dt>Registered from</dt><dd>' + esc(netLine(p.regIp, p.regGeoCountry, p.regGeoCity)) + '</dd></div>' +
      '<div><dt>Latest seen</dt><dd>' + esc(latest ? netLine(latest.ip, latest.country, latest.city) : 'Not captured') + '</dd></div>' +
      (latest && latest.ts ? '<div><dt>Latest seen at</dt><dd>' + esc(fmtDhaka(latest.ts)) + '</dd></div>' : '') +
      '</dl>' +
      ((p.regIp || latest) ? '' : '<p class="fineprint">IP and coarse location are stamped by the server when records arrive. They appear here after this person\'s phone next syncs on the v78 build.</p>') +
      '</article>';

    /* --- palm as CODE: the sealed-bank fingerprint --- */
    var counts = profileCounts(p);
    html += '<article class="profile-card detail-card">' +
      '<h3>Palm — encrypted code</h3>';
    if (p.bankFingerprint) {
      html += '<dl class="profile-meta">' +
        '<div><dt>Envelope</dt><dd>' + esc(p.enc === 'v1' ? 'enc.v1 (sealed)' : 'encoded') + '</dd></div>' +
        '<div><dt>Templates</dt><dd>' + counts.edcc + ' EDCC · ' + counts.emb + ' PalmNet</dd></div>' +
        (typeof p.edccBytes === 'number' ? '<div><dt>EDCC template size</dt><dd>' + p.edccBytes + ' bytes (sealed)</dd></div>' : '') +
        (typeof p.neuralDims === 'number' ? '<div><dt>PalmNet vector</dt><dd>' + p.neuralDims + ' dimensions (sealed)</dd></div>' : '') +
        '<div><dt>Image</dt><dd>No consented image is linked to this person — research frames are anonymous by design (they carry only an anonymous research code, never a name or Biom ID), so no image can be shown here.</dd></div>' +
        '</dl>' +
        '<p class="field-note">Bank fingerprint (SHA-256 of the sealed bank)</p>' +
        '<p class="mono">' + esc(p.bankFingerprint) + '</p>' +
        '<p class="fineprint">This fingerprint identifies the sealed template bank and changes whenever the bank changes. It cannot be turned back into a palm — no palm image exists anywhere in this system.</p>';
    } else {
      html += '<p class="fineprint">The bank fingerprint appears here once the API runs the v78 build. The palm itself is never shown — it exists only as sealed template code.</p>' +
        '<p class="fineprint">Image: no consented image is linked to this person — research frames are anonymous by design (anonymous research code only, never a name or Biom ID), so no image can be shown here.</p>';
    }
    html += '</article>';

    /* --- wallet: balance + full ledger --- */
    var totals = walletTotals(p);
    /* v82 (Phase 6, field audit): the linked-wallet rows. The
       API stores a walletLink on the profile record (provider +
       MASKED wallet number, bKash agreement links) but its full
       summary does not serve that field yet — so when a summary
       ever carries it, it renders here; until then the rows say
       so plainly instead of guessing. The rail can also be read
       honestly from the ledger mirror itself: every Add entry
       carries the account type it came through. The full wallet
       number is never stored server-side — only the masked
       label on top-up entries — and is never invented here. */
    var linkProvider = p.walletLink && p.walletLink.provider ? String(p.walletLink.provider) : '';
    var linkMasked = p.walletLink && p.walletLink.maskedWallet ? String(p.walletLink.maskedWallet) : '';
    var railSet = [];
    if (linkProvider) railSet.push(linkProvider);
    if (p.wallet && Array.isArray(p.wallet.statement)) {
      p.wallet.statement.forEach(function (e) {
        if (e && e.kind === 'add' && e.accountType && railSet.indexOf(e.accountType) === -1) railSet.push(e.accountType);
      });
    }
    var railLabel = railSet.length
      ? railSet.map(function (r) { return r === 'bkash' ? 'bKash' : (r === 'nagad' ? 'Nagad' : r); }).join(' · ')
      : 'Not captured';
    html += '<article class="profile-card detail-card">' +
      '<h3>Wallet</h3>' +
      '<dl class="profile-meta">' +
      '<div><dt>Linked wallet</dt><dd>' + esc(linkMasked || 'Not served by the API summary yet') + '</dd></div>' +
      '<div><dt>Rail</dt><dd>' + esc(railLabel) + '</dd></div>' +
      '</dl>' +
      '<p class="fineprint">The full wallet number is never stored on the server — a linked wallet is kept masked, and top-up entries below carry their masked account label.</p>';
    if (p.wallet && typeof p.wallet.balance === 'number') {
      var rows = [];
      (p.wallet.statement || []).forEach(function (e) {
        if (!e) return;
        var detail = '', sign = '';
        if (e.kind === 'add') { detail = 'Add money' + (e.accountLabel ? ' · ' + e.accountLabel : ''); sign = '+'; }
        else if (e.kind === 'send') { detail = 'Send money → ' + (e.counterpartyName || '—') + (e.counterpartyId ? ' (' + e.counterpartyId + ')' : ''); sign = '−'; }
        else if (e.kind === 'receive') { detail = 'Received ← ' + (e.counterpartyName || '—') + (e.counterpartyId ? ' (' + e.counterpartyId + ')' : ''); sign = '+'; }
        else return;
        rows.push({ ts: e.ts || 0, detail: detail, amount: sign + fmtMoney(e.amount), after: typeof e.balanceAfter === 'number' ? fmtMoney(e.balanceAfter) : '—' });
      });
      (p.pays || []).forEach(function (x) {
        if (!x) return;
        rows.push({
          ts: x.ts || 0,
          detail: 'Biom Pay · ' + (x.store || '—') + (x.provider ? ' · ' + x.provider : '') + (x.status && x.status !== 'Completed' ? ' · ' + x.status : ''),
          amount: '−' + fmtMoney(x.amount), after: '—'
        });
      });
      rows.sort(function (a, b) { return b.ts - a.ts; });
      html += '<p class="wallet-balance">' + esc(fmtMoney(totals.balance)) + '</p>' +
        '<dl class="profile-meta">' +
        '<div><dt>Total added</dt><dd>' + esc(fmtMoney(totals.added)) + '</dd></div>' +
        '<div><dt>Total sent</dt><dd>' + esc(fmtMoney(totals.sent)) + '</dd></div>' +
        '<div><dt>Total received</dt><dd>' + esc(fmtMoney(totals.received)) + '</dd></div>' +
        '<div><dt>Total paid (Biom Pay)</dt><dd>' + esc(fmtMoney(totals.paid)) + '</dd></div>' +
        '</dl>' +
        (rows.length
          ? '<p class="field-note">' + rows.length + (rows.length === 1 ? ' entry' : ' entries') + ', newest first</p>' +
            '<div class="ledger-list">' +
            rows.map(function (r) {
              return '<div class="ledger-row">' +
                '<div class="ledger-main"><span class="ledger-detail">' + esc(r.detail) + '</span>' +
                '<span class="ledger-amount num">' + esc(r.amount) + '</span></div>' +
                '<div class="ledger-sub"><span>' + esc(fmtDhaka(r.ts)) + '</span>' +
                (r.after !== '—' ? '<span>Balance after ' + esc(r.after) + '</span>' : '') +
                '</div></div>';
            }).join('') +
            '</div>'
          : '<p class="empty-note">No wallet activity recorded yet.</p>') +
        '<p class="fineprint">The ledger mirrors the wallet statement the app keeps on the phone (same running balance), plus the Biom Pay records. It appears here after the phone syncs on the v78 build.</p>';
    } else {
      html += '<p class="fineprint">Wallet records appear here after this person\'s phone next syncs on the v78 build — the wallet statement has always lived on the device and now mirrors to your API with each sync.</p>';
    }
    html += '</article>';
    return html;
  }

  /* The Block / Unblock control inside the person drawer.
     ui = { adminKeyPresent, armed, busy, message, tone }.
     Buttons carry data-action attributes; the wiring owns the
     clicks and re-renders this block on every state change. */
  function renderBlockActionHtml(p, ui, scans) {
    if (!p || p.deleted === true) return '';
    ui = ui || {};
    var msg = ui.message
      ? (ui.tone === 'err'
        ? '<p class="form-error" role="alert">' + esc(ui.message) + '</p>'
        : '<p class="ok-note" role="status">' + esc(ui.message) + '</p>')
      : '';
    var open = '<article class="profile-card detail-card"><h3>Access control</h3>';
    /* v79 (category e): a rollback-guard tamper flag is shown
       here for the Chairman's judgement — the server refused to
       roll this wallet's ledger back; it is a flag, never an
       automatic block, because a stale second device is a
       legitimate cause. */
    var tamperHtml = (p.tamperFlags && typeof p.tamperFlags.rollbackAttempts === 'number' && p.tamperFlags.rollbackAttempts > 0)
      ? '<p class="form-error" role="alert">Ledger rollback attempts refused: ' + p.tamperFlags.rollbackAttempts +
        (typeof p.tamperFlags.lastRollbackTs === 'number' ? ' (most recently ' + esc(fmtDhaka(p.tamperFlags.lastRollbackTs)) + ')' : '') +
        '. A stale second device can cause this — if it was not theirs, consider blocking.</p>'
      : '';
    /* v80 (Gaps 1 + 2): two evidence flags computed from the
       scan records, in the same flag-not-verdict language as
       the tamper flag above.
       IMPERSONATION: denied scans whose presented palm scored
       close to THIS person's palm (the record's cross-match
       fields name them). This person is the TARGET — the flag
       exists so the Chairman sees they are being targeted;
       the server never blocks a target for it (attributed
       events block the attacker's account instead).
       DUPLICATE ENROLMENT: enrolment refusals naming this
       person — a device already holding their palm refused to
       enrol it again under a new identity, and stored nothing.
       Field-test records are exercises, never evidence, and
       are excluded from both flags. */
    var crossCount = 0, crossLatest = 0, crossTopEdcc = null, crossTopNeural = null, dupCount = 0, dupLatest = 0;
    (scans || []).forEach(function (s) {
      if (!s || s.fieldTest === true) return;
      /* v80 Seat 1 fixes: the flag counts DENIED records only
         (correct by this code, not only by the app's
         construction), and the strongest score is tracked PER
         SYSTEM — EDCC and PalmNet scores live on different
         scales (bars 0.32 vs 0.5895), so one raw maximum
         across both would systematically mislead. */
      if (/denied/i.test(s.result || '') && (s.crossEdccId === p.biomId || s.crossNeuralId === p.biomId)) {
        crossCount++;
        if ((s.ts || 0) > crossLatest) crossLatest = s.ts || 0;
        if (s.crossEdccId === p.biomId && typeof s.crossEdccScore === 'number' && (crossTopEdcc === null || s.crossEdccScore > crossTopEdcc)) crossTopEdcc = s.crossEdccScore;
        if (s.crossNeuralId === p.biomId && typeof s.crossNeuralScore === 'number' && (crossTopNeural === null || s.crossNeuralScore > crossTopNeural)) crossTopNeural = s.crossNeuralScore;
      }
      if (s.kind === 'enrol' && s.biomId === p.biomId && /duplicate/i.test(s.result || '')) {
        dupCount++;
        if ((s.ts || 0) > dupLatest) dupLatest = s.ts || 0;
      }
    });
    var flagsHtml = '';
    if (crossCount > 0) {
      var crossTopParts = [];
      if (crossTopEdcc !== null) crossTopParts.push('EDCC ' + crossTopEdcc.toFixed(3));
      if (crossTopNeural !== null) crossTopParts.push('PalmNet ' + crossTopNeural.toFixed(3));
      flagsHtml += '<p class="form-error" role="alert">Impersonation attempts targeting this person: ' + crossCount + ' recorded' +
        (crossLatest ? ' (most recently ' + esc(fmtDhaka(crossLatest)) + ')' : '') +
        (crossTopParts.length ? '; strongest: ' + crossTopParts.join(' · ') : '') +
        '. These are denied scans where a presented palm scored close to this person\'s palm. Attempts from an enrolled attacker\'s own device count toward an auto-block of the attacker — this person is never blocked for being targeted.</p>';
    }
    if (dupCount > 0) {
      flagsHtml += '<p class="form-error" role="alert">Duplicate enrolment refused: ' + dupCount + ' attempt' + (dupCount === 1 ? '' : 's') +
        ' to enrol this palm again under a new identity on a device already holding it' +
        (dupLatest ? ' (most recently ' + esc(fmtDhaka(dupLatest)) + ')' : '') +
        '. Each enrolment was refused and nothing was created.</p>';
    }
    tamperHtml += flagsHtml;
    if (!ui.adminKeyPresent) {
      return open + tamperHtml +
        '<p class="fineprint">Blocking is not set up on this browser yet. Add the <strong>admin key</strong> in Settings → Connection to enable Block / Unblock here.</p>' +
        '<button type="button" class="btn btn-light" data-action="open-settings">Open Settings</button>' +
        msg + '</article>';
    }
    if (p.blocked === true) {
      return open + tamperHtml +
        '<p><span class="badge badge-denied">Blocked</span></p>' +
        '<dl class="profile-meta">' +
        '<div><dt>Blocked by</dt><dd>' + (p.blockedBy === 'system' ? 'System (auto-block)' : 'Chairman') + '</dd></div>' +
        (p.blockedTs ? '<div><dt>Blocked at</dt><dd>' + esc(fmtDhaka(p.blockedTs)) + '</dd></div>' : '') +
        (p.blockedReason ? '<div><dt>Reason</dt><dd>' + esc(p.blockedReason) + '</dd></div>' : '') +
        (Array.isArray(p.blockedIps) && p.blockedIps.length ? '<div><dt>Blocked IPs</dt><dd>' + esc(p.blockedIps.join(', ')) + '</dd></div>' : '') +
        '</dl>' +
        '<p class="fineprint">While blocked, this person\'s sync writes and payments are refused, and the IP addresses their account has been seen on are blocked too — a new wallet cannot be registered from the same network. Unblocking restores sync and payments and lifts the IP block — but their devices stay revoked, and re-registering a device is the path back.</p>' +
        (ui.armed
          ? '<button type="button" class="btn btn-primary" data-action="unblock-confirm"' + (ui.busy ? ' disabled' : '') + '>' + (ui.busy ? 'Working…' : 'Confirm unblock') + '</button> ' +
            '<button type="button" class="btn btn-light" data-action="block-cancel"' + (ui.busy ? ' disabled' : '') + '>Cancel</button>'
          : '<button type="button" class="btn btn-light" data-action="unblock-arm"' + (ui.busy ? ' disabled' : '') + '>Unblock this person</button>') +
        msg + '</article>';
    }
    return open + tamperHtml +
      '<p class="fineprint">Blocking flags this Biom ID and revokes the person\'s devices at once. The API then refuses their sync writes and payments with a clear blocked error, and the app shows “This account has been blocked”. Blocking also blocks the IP addresses this account has been seen on, so a new wallet cannot be registered from the same network; unblocking lifts the IP block. The action is recorded in the admin log (Settings → Admin activity).</p>' +
      (ui.armed
        ? '<label class="field"><span>Reason (optional)</span>' +
          '<input type="text" class="block-reason-input" placeholder="Why is this person blocked?" maxlength="280" spellcheck="false"></label>' +
          '<button type="button" class="btn btn-danger" data-action="block-confirm"' + (ui.busy ? ' disabled' : '') + '>' + (ui.busy ? 'Working…' : 'Confirm block') + '</button> ' +
          '<button type="button" class="btn btn-light" data-action="block-cancel"' + (ui.busy ? ' disabled' : '') + '>Cancel</button>'
        : '<button type="button" class="btn btn-danger" data-action="block-arm"' + (ui.busy ? ' disabled' : '') + '>Block this person</button>') +
      msg + '</article>';
  }

  function renderAdminLogHtml(entries) {
    if (!Array.isArray(entries) || !entries.length) {
      return '<p class="empty-note">No block or unblock has been recorded yet.</p>';
    }
    /* v79: the log also carries WHO acted — the Chairman, or
       the system itself (auto-block / auto-revocation) — and
       device-revocation entries from the tamper rules. Entries
       written before v79 carry no actor: they were all the
       Chairman's manual actions and render as such. */
    function actionBadge(e) {
      if (e.action === 'revoke-device') return '<span class="badge badge-denied">Device revoked</span>';
      if (e.action === 'block') return e.actor === 'system'
        ? '<span class="badge badge-denied">Auto-block</span>'
        : '<span class="badge badge-denied">Block</span>';
      return '<span class="badge badge-verified">Unblock</span>';
    }
    function actorLabel(e) {
      return e.actor === 'system' ? 'System (auto)' : 'Chairman';
    }
    function ipLine(e) {
      var parts = [];
      if (Array.isArray(e.blockedIps) && e.blockedIps.length) parts.push('IPs blocked: ' + e.blockedIps.join(', '));
      if (Array.isArray(e.liftedIps) && e.liftedIps.length) parts.push('IPs lifted: ' + e.liftedIps.join(', '));
      return parts.length ? '<div class="sub">' + esc(parts.join(' · ')) + '</div>' : '';
    }
    /* v79 render-gate fix: the six-column log (with the long
       auto-block reasons) is wider than a phone card — it sits
       in a horizontal scroll wrap so the page itself never
       overflows; on desktop the table fits and nothing scrolls. */
    return '<div class="table-scroll"><table class="scans-table mini-table"><thead><tr>' +
      '<th scope="col">When (Dhaka)</th><th scope="col">Action</th><th scope="col">By</th><th scope="col">Biom ID</th><th scope="col">Reason</th><th scope="col">Devices revoked</th>' +
      '</tr></thead><tbody>' +
      entries.map(function (e) {
        return '<tr>' +
          '<td class="time">' + esc(fmtDhaka(e.ts)) + '</td>' +
          '<td>' + actionBadge(e) + '</td>' +
          '<td>' + esc(actorLabel(e)) + '</td>' +
          '<td>' + esc(e.biomId || '—') + '</td>' +
          '<td>' + esc(e.reason || '—') + ipLine(e) + '</td>' +
          '<td class="num">' + esc(Array.isArray(e.revokedDeviceIds) ? e.revokedDeviceIds.length : 0) + '</td>' +
          '</tr>';
      }).join('') +
      '</tbody></table></div>';
  }

  /* v79: the blocked-IP registry (Settings → Admin activity).
     An IP stays blocked while any blocked person's entry names
     it; unblocking that person lifts their entries. */
  function renderBlockedIpsHtml(entries) {
    if (!Array.isArray(entries) || !entries.length) {
      return '<p class="empty-note">No IP addresses are blocked right now. When a person is blocked, the networks their account has been seen on are blocked here too, so they cannot register a new wallet from the same network.</p>';
    }
    return '<div class="table-scroll"><table class="scans-table mini-table"><thead><tr>' +
      '<th scope="col">IP address</th><th scope="col">Linked Biom ID</th><th scope="col">Blocked at (Dhaka)</th><th scope="col">By</th>' +
      '</tr></thead><tbody>' +
      entries.map(function (e) {
        return '<tr>' +
          '<td>' + esc(e.ip || '') + '</td>' +
          '<td>' + esc(e.biomId || '') + '</td>' +
          '<td class="time">' + esc(fmtDhaka(e.ts)) + '</td>' +
          '<td>' + esc(e.actor === 'system' ? 'System (auto)' : 'Chairman') + '</td>' +
          '</tr>';
      }).join('') +
      '</tbody></table></div>';
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

  /* v81: the research-frame count for the stats strip. The
     count route is ADMIN-key gated on the API (it sits with
     the other admin routes), so this goes through adminFetch
     with the sealed admin key; without one it resolves null.
     Any failure (older API, route absent, network) resolves
     null — the card simply stays hidden; research counting
     must never break the dashboard's main load. */
  function loadResearchCount(endpoint, adminKey, fetchFn) {
    if (!adminKey) return Promise.resolve(null);
    return adminFetch(endpoint, adminKey, '/api/admin/research', null, fetchFn)
      .then(function (j) {
        if (!j || typeof j.frames !== 'number') return null;
        return { bundles: typeof j.bundles === 'number' ? j.bundles : 0, frames: j.frames, byDay: j.byDay || {} };
      })
      .catch(function () { return null; });
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

  /* ---------------- v78: admin API (Block / Unblock / log) ----
     Gated server-side by BIOM_ADMIN_KEY; the dashboard sends the
     admin key (unsealed from the same password seal as the read
     key) in the x-admin-key header only. Errors keep the parsed
     body on err.body so the UI can tell "not configured" (503)
     from "key refused" (401) from "blocked" states. */
  function adminFetch(endpoint, adminKey, path, body, fetchFn) {
    var f = fetchFn || (typeof fetch !== 'undefined' ? fetch : null);
    if (!f) return Promise.reject(apiError(0, 'fetch is not available'));
    var base = String(endpoint || '').replace(/\/+$/, '');
    var opts = { method: body ? 'POST' : 'GET', headers: { 'x-admin-key': adminKey, 'Accept': 'application/json' } };
    if (body) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    return f(base + path, opts).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (json) {
        if (!res.ok) {
          var e = apiError(res.status, (json && json.error) || ('HTTP ' + res.status));
          e.body = json || {};
          throw e;
        }
        return json;
      });
    });
  }

  function adminBlock(endpoint, adminKey, biomId, reason, fetchFn) {
    return adminFetch(endpoint, adminKey, '/api/admin/block', { biomId: biomId, reason: reason || '' }, fetchFn);
  }

  function adminUnblock(endpoint, adminKey, biomId, fetchFn) {
    return adminFetch(endpoint, adminKey, '/api/admin/unblock', { biomId: biomId }, fetchFn);
  }

  function adminLog(endpoint, adminKey, fetchFn) {
    return adminFetch(endpoint, adminKey, '/api/admin/log', null, fetchFn)
      .then(function (json) { return Array.isArray(json.entries) ? json.entries : []; });
  }

  function adminBlockedIps(endpoint, adminKey, fetchFn) {
    return adminFetch(endpoint, adminKey, '/api/admin/blocked-ips', null, fetchFn)
      .then(function (json) { return Array.isArray(json.entries) ? json.entries : []; });
  }

  /* v82 (Phase 6): research-frame withdrawal deletion. The API
     (v81) deletes every stored bundle for ONE anonymous research
     code via POST /api/admin/research-delete {researchId} and
     answers {ok, researchId, removed} — removed = bundles removed.
     Until v82 the dashboard showed the research count but had NO
     control for this route, so the v81 privacy promise could not
     be carried out from the dashboard at all. */
  function adminResearchDelete(endpoint, adminKey, researchId, fetchFn) {
    return adminFetch(endpoint, adminKey, '/api/admin/research-delete', { researchId: researchId }, fetchFn);
  }

  /* The research-delete control (Settings → Admin activity).
     ui = { adminKeyPresent, code, armed, busy, message, tone }.
     Two-step by design (Fraud Checking seat): typing a code and
     tapping Delete only ARMS the control; the destructive POST
     fires only from the separate Confirm button, and the wiring
     refuses to confirm if the code changed after arming. With no
     admin key sealed the control explains itself and renders no
     actionable button at all. */
  function renderResearchDeleteHtml(ui) {
    ui = ui || {};
    var msg = ui.message
      ? (ui.tone === 'err'
        ? '<p class="form-error" role="alert">' + esc(ui.message) + '</p>'
        : '<p class="ok-note" role="status">' + esc(ui.message) + '</p>')
      : '';
    if (!ui.adminKeyPresent) {
      return '<p class="fineprint">Research-frame deletion is not set up on this browser yet. Add the <strong>admin key</strong> in Connection above to enable it — deletion is protected by the admin key, not the read key.</p>' + msg;
    }
    if (ui.armed) {
      return '<p class="fineprint">This permanently deletes every stored research bundle for this code from the research store. It cannot be undone from here.</p>' +
        '<p class="mono">' + esc(ui.code || '') + '</p>' +
        '<button type="button" class="btn btn-danger" data-action="research-delete-confirm"' + (ui.busy ? ' disabled' : '') + '>' + (ui.busy ? 'Working…' : 'Confirm delete') + '</button> ' +
        '<button type="button" class="btn btn-light" data-action="research-delete-cancel"' + (ui.busy ? ' disabled' : '') + '>Cancel</button>' + msg;
    }
    return '<label class="field"><span>Research code</span>' +
      '<input type="text" id="researchCodeInput" placeholder="res-…" spellcheck="false" autocomplete="off" value="' + esc(ui.code || '') + '"></label>' +
      '<button type="button" class="btn btn-danger" data-action="research-delete-arm"' + (ui.busy ? ' disabled' : '') + '>Delete stored frames for this code</button>' + msg;
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
      /* v78: the admin key (Block/Unblock control) rides the
         same seal as the read key — same password, same
         per-origin storage, never plain text. Absent = ''. */
      var payload = JSON.stringify({ endpoint: creds.endpoint, readKey: creds.readKey, adminKey: creds.adminKey || '' });
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
        /* v78: seals written before v78 carry no adminKey — they
           open with an empty one (blocking simply stays unset up
           until the key is added in Settings). */
        return { endpoint: obj.endpoint || DEFAULT_ENDPOINT, readKey: obj.readKey, adminKey: obj.adminKey || '' };
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
    fmtDhakaShort: fmtDhakaShort,
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
    sortProfiles: sortProfiles,
    renderBanksRowsHtml: renderBanksRowsHtml,
    renderBankDetailHtml: renderBankDetailHtml,
    fmtDuration: fmtDuration,
    isSlowScan: isSlowScan,
    durationHtml: durationHtml,
    renderRecentScansRowsHtml: renderRecentScansRowsHtml,
    renderVaultHealthHtml: renderVaultHealthHtml,
    renderScanCardsHtml: renderScanCardsHtml,
    fmtMoney: fmtMoney,
    netLine: netLine,
    latestNet: latestNet,
    walletTotals: walletTotals,
    renderPersonControlHtml: renderPersonControlHtml,
    renderBlockActionHtml: renderBlockActionHtml,
    renderAdminLogHtml: renderAdminLogHtml,
    renderBlockedIpsHtml: renderBlockedIpsHtml,
    adminBlock: adminBlock,
    adminUnblock: adminUnblock,
    adminLog: adminLog,
    adminBlockedIps: adminBlockedIps,
    adminResearchDelete: adminResearchDelete,
    renderResearchDeleteHtml: renderResearchDeleteHtml,
    fetchJson: fetchJson,
    loadAll: loadAll,
    loadResearchCount: loadResearchCount
  };

  if (typeof module !== 'undefined' && module.exports) module.exports = Core;
  if (typeof window !== 'undefined') window.TsgBiomCore = Core;

  /* ---------------- browser wiring ---------------- */

  if (typeof document === 'undefined' || typeof window === 'undefined') return;

  var els = {};
  var state = { scans: [], profiles: [], research: null, loading: false, timer: null, bankSort: { key: 'name', dir: 1 }, displayedProfiles: [] };
  /* v63: the unsealed credentials live ONLY in this variable —
     memory, never storage. Locked means null, and refresh()
     does nothing while locked, so no API call can happen
     before the password unlocks the seal. */
  var sessionCreds = null;
  var setupMode = 'fresh'; // 'fresh' | 'migrate' (pre-v63 plaintext) | 'manage' (v78 Settings, unlocked)
  /* v78: the drawer Block/Unblock control's transient state. */
  var drawerUi = { biomId: '', armed: false, busy: false, message: '', tone: '' };
  /* v82: the research-delete control's transient state. armedCode
     pins the code that was armed — a confirm with a different code
     is refused, so the destructive POST can only ever target the
     exact code the Chairman read back in the confirm step. */
  var researchUi = { armed: false, armedCode: '', busy: false, message: '', tone: '' };

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

  function hideAllViews() {
    els.lockView.hidden = true;
    els.firstRunView.hidden = true;
    els.settingsView.hidden = true;
    els.mainView.hidden = true;
  }

  /* v78: the front door when NO seal exists is a quiet notice —
     never the setup form. The form lives in Settings; this
     notice is the only path to it before a seal exists. */
  function showFirstRun(mode) {
    stopAutoRefresh();
    setupMode = mode || 'fresh';
    hideAllViews();
    els.firstRunView.hidden = false;
    els.topbarActions.hidden = true;
    var migrate = setupMode === 'migrate';
    els.firstRunTextFresh.hidden = migrate;
    els.firstRunTextMigrate.hidden = !migrate;
  }

  /* v78: the Settings page. mode 'fresh' | 'migrate' | 'manage'.
     In manage mode the session is live (topbar stays, Back shows,
     Admin activity loads); the form edits the sealed credentials
     and saving re-seals under the re-entered current password. */
  function showSettings(mode, message) {
    if (mode !== 'manage') stopAutoRefresh();
    setupMode = mode || 'fresh';
    hideAllViews();
    els.settingsView.hidden = false;
    var manage = setupMode === 'manage';
    var migrate = setupMode === 'migrate';
    els.topbarActions.hidden = !manage;
    els.settingsBackBtn.hidden = !manage;
    els.adminActivityCard.hidden = !manage;
    els.setupIntroFresh.hidden = manage || migrate;
    els.setupIntroMigrate.hidden = !migrate;
    els.setupIntroManage.hidden = !manage;
    els.fieldEndpointWrap.hidden = migrate;
    els.fieldKeyWrap.hidden = migrate;
    /* hidden or optional fields must not block form validation */
    els.endpointInput.required = !migrate && !manage;
    els.readKeyInput.required = !migrate && !manage;
    els.passwordConfirmInput.required = !manage;
    els.fieldConfirmWrap.hidden = manage;
    els.fieldAdminRemoveWrap.hidden = true;
    els.adminKeyRemoveInput.checked = false;
    els.passwordLabel.textContent = manage ? 'Dashboard password (to save changes)' : 'Dashboard password';
    els.connectBtn.textContent = migrate ? 'Seal the key and continue' : (manage ? 'Save connection settings' : 'Connect');
    if (manage && sessionCreds) {
      els.endpointInput.value = sessionCreds.endpoint;
      els.endpointInput.disabled = true; /* the endpoint is fixed for this build (CSP) */
      els.readKeyInput.value = '';
      els.readKeyInput.placeholder = 'Leave blank to keep the saved read key';
      els.adminKeyInput.value = '';
      els.adminKeyInput.placeholder = sessionCreds.adminKey ? 'Saved — leave blank to keep it' : 'Your BIOM_ADMIN_KEY';
      els.adminKeyState.textContent = sessionCreds.adminKey
        ? 'An admin key is saved on this browser (sealed). Block / Unblock is enabled.'
        : 'No admin key saved yet — Block / Unblock stays disabled until one is added.';
      els.fieldAdminRemoveWrap.hidden = !sessionCreds.adminKey;
      renderResearchDelete();
      loadAdminLog();
    } else {
      els.endpointInput.disabled = false;
      els.readKeyInput.placeholder = 'Your READ_KEY';
      els.adminKeyInput.placeholder = 'Your BIOM_ADMIN_KEY';
      els.adminKeyState.textContent = 'Optional. The admin key enables Block / Unblock and is sealed under the same password.';
    }
    if (message) {
      els.setupError.textContent = message;
      els.setupError.hidden = false;
    } else {
      els.setupError.hidden = true;
    }
  }

  function showLock(message) {
    stopAutoRefresh();
    hideAllViews();
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
    hideAllViews();
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
    var stats = Core.computeStats(state.scans, state.profiles, state.research);
    els.statsGrid.innerHTML = Core.renderStatsHtml(stats);

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
    if (els.scansCards) els.scansCards.innerHTML = Core.renderScanCardsHtml(filtered);
    els.scansEmpty.hidden = filtered.length !== 0;

    /* v66: Overview panels + Palm Banks table/drawer data */
    if (els.recentScansBody) {
      els.recentScansBody.innerHTML = Core.renderRecentScansRowsHtml(state.scans);
      els.recentScansEmpty.hidden = state.scans.length !== 0;
    }
    if (els.vaultHealth) els.vaultHealth.innerHTML = Core.renderVaultHealthHtml(state.profiles);
    var pq = els.profileSearchInput ? els.profileSearchInput.value.trim().toLowerCase() : '';
    var pstatus = els.profileStatusFilter ? els.profileStatusFilter.value : '';
    var shownProfiles = state.profiles.filter(function (p) {
      if (pstatus === 'live' && p.deleted === true) return false;
      if (pstatus === 'removed' && p.deleted !== true) return false;
      if (pq) {
        var hay = (String(p.name || '') + ' ' + String(p.biomId || '')).toLowerCase();
        if (hay.indexOf(pq) === -1) return false;
      }
      return true;
    });
    state.displayedProfiles = shownProfiles;
    els.profilesGrid.innerHTML = Core.renderProfilesHtml(shownProfiles);
    if (els.banksTableBody) {
      els.banksTableBody.innerHTML = Core.renderBanksRowsHtml(
        Core.sortProfiles(shownProfiles, state.bankSort.key, state.bankSort.dir));
    }
    if (els.banksEmpty) els.banksEmpty.hidden = !(state.profiles.length !== 0 && shownProfiles.length === 0);
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
      if (els.banksTableBody) els.banksTableBody.innerHTML = '<tr class="skeltrow"><td colspan="7"><div class="skelbar w65"></div></td></tr>' +
        '<tr class="skeltrow"><td colspan="7"><div class="skelbar w40"></div></td></tr>';
      if (els.recentScansBody) els.recentScansBody.innerHTML = '<tr class="skeltrow"><td colspan="3"><div class="skelbar w85"></div></td></tr>';
      if (els.scansCards) els.scansCards.innerHTML = '<div class="skelcard"><div class="skelbar w65"></div><div class="skelbar w40"></div></div>';
      els.profilesGrid.innerHTML = '<div class="skelcard"><div class="skelbar w65"></div><div class="skelbar w40"></div><div class="skelbar w85"></div></div>' +
        '<div class="skelcard"><div class="skelbar w65"></div><div class="skelbar w40"></div><div class="skelbar w85"></div></div>';
    }
    return Core.loadAll(creds.endpoint, creds.readKey)
      .then(function (data) {
        state.scans = data.scans;
        state.profiles = data.profiles;
        /* v81: refresh the research-frame count alongside the
           main load; it resolves null on any failure and only
           ever adds its stats card. */
        Core.loadResearchCount(creds.endpoint, creds.adminKey).then(function (rc) {
          state.research = rc;
          if (rc) renderAll();
        });
        els.statusBanner.hidden = true;
        if (els.lastUpdatedLine) els.lastUpdatedLine.textContent = 'Last updated ' + Core.fmtDhaka(Date.now());
        renderAll();
      })
      .catch(function (err) {
        /* v64: a failed cold load leaves no skeleton behind. */
        if (!state.scans.length && !state.profiles.length) {
          els.statsGrid.innerHTML = '';
          els.profilesGrid.innerHTML = '';
          if (els.banksTableBody) els.banksTableBody.innerHTML = '';
          if (els.recentScansBody) els.recentScansBody.innerHTML = '';
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

  /* v73 (Seat 1 dashboard F4): locking or disconnecting must
     not leave the last rendered records sitting in the hidden
     DOM (names, Biom IDs, device labels readable by anyone who
     unhides the node). Clear every rendered record container;
     the renderers repaint them on the next unlock + refresh. */
  function clearRendered() {
    ['statsGrid', 'profilesGrid', 'scansBody', 'banksTableBody', 'recentScansBody', 'scansCards', 'bankDrawerBody', 'vaultHealth', 'adminLogBody', 'blockedIpsBody', 'researchDeleteBody'].forEach(function (id) {
      if (els[id]) els[id].innerHTML = '';
    });
  }

  function disconnect() {
    sessionCreds = null;
    researchUi = { armed: false, armedCode: '', busy: false, message: '', tone: '' };
    clearStored();
    state.scans = [];
    state.profiles = [];
    clearRendered();
    els.readKeyInput.value = '';
    els.adminKeyInput.value = '';
    els.passwordInput.value = '';
    els.passwordConfirmInput.value = '';
    /* v78: after disconnecting there is no seal, so the front
       door is the quiet first-run notice again — never the form. */
    showFirstRun('fresh');
  }

  /* v78: the admin activity log in Settings. Read with the admin
     key only; a 503 from the API means BIOM_ADMIN_KEY is not set
     on the server and the copy says exactly that. */
  function loadAdminLog() {
    if (!sessionCreds || !els.adminLogBody) return;
    if (!sessionCreds.adminKey) {
      els.adminLogBody.innerHTML = '<p class="empty-note">Add the admin key in Connection above to read the admin log — it is protected by the admin key, not the read key.</p>';
      if (els.blockedIpsBody) els.blockedIpsBody.innerHTML = '';
      return;
    }
    els.adminLogBody.innerHTML = '<p class="fineprint">Loading the admin log…</p>';
    /* v79: the blocked-IP registry loads alongside the log —
       same key, same card. A failure here never hides the log:
       the registry area carries its own quiet note. */
    if (els.blockedIpsBody) {
      els.blockedIpsBody.innerHTML = '<p class="fineprint">Loading blocked IP addresses…</p>';
      Core.adminBlockedIps(sessionCreds.endpoint, sessionCreds.adminKey)
        .then(function (entries) {
          els.blockedIpsBody.innerHTML = Core.renderBlockedIpsHtml(entries);
        })
        .catch(function () {
          els.blockedIpsBody.innerHTML = '<p class="empty-note">Could not load the blocked IP list. Try Refresh log.</p>';
        });
    }
    Core.adminLog(sessionCreds.endpoint, sessionCreds.adminKey)
      .then(function (entries) {
        els.adminLogBody.innerHTML = Core.renderAdminLogHtml(entries);
      })
      .catch(function (err) {
        if (err && err.status === 503) {
          els.adminLogBody.innerHTML = '<p class="empty-note">Admin controls are not configured on the server. Set BIOM_ADMIN_KEY in the API project\'s environment variables on Vercel and redeploy — until then block, unblock and this log stay off (they never fail open).</p>';
        } else if (err && err.status === 401) {
          els.adminLogBody.innerHTML = '<p class="empty-note">The admin key was refused by the API. Check the admin key in Connection above against BIOM_ADMIN_KEY on the server.</p>';
        } else {
          els.adminLogBody.innerHTML = '<p class="empty-note">Could not load the admin log. Check your connection and try Refresh log.</p>';
        }
      });
  }

  /* v82: the research-delete control (Settings → Admin activity).
     Defined before lock()/disconnect() reset it. The confirm step
     re-reads the armed code: if the input changed after arming,
     nothing is sent and the control disarms with the reason. */
  function renderResearchDelete() {
    if (!els.researchDeleteBody) return;
    var input = els.researchDeleteBody.querySelector('#researchCodeInput');
    var code = researchUi.armed ? researchUi.armedCode : (input ? input.value : (researchUi.armedCode || ''));
    els.researchDeleteBody.innerHTML = Core.renderResearchDeleteHtml({
      adminKeyPresent: !!(sessionCreds && sessionCreds.adminKey),
      code: code, armed: researchUi.armed, busy: researchUi.busy,
      message: researchUi.message, tone: researchUi.tone
    });
  }

  function runResearchDelete() {
    if (!sessionCreds || !sessionCreds.adminKey || researchUi.busy) return;
    var code = researchUi.armedCode;
    researchUi.busy = true;
    researchUi.message = '';
    renderResearchDelete();
    Core.adminResearchDelete(sessionCreds.endpoint, sessionCreds.adminKey, code)
      .then(function (res) {
        researchUi.busy = false;
        researchUi.armed = false;
        researchUi.armedCode = '';
        researchUi.tone = 'ok';
        var removed = res && typeof res.removed === 'number' ? res.removed : 0;
        researchUi.message = removed > 0
          ? 'Deleted. ' + removed + ' stored bundle' + (removed === 1 ? '' : 's') + ' removed for that research code.'
          : 'Done — no stored bundles were found for that research code, so nothing was removed.';
        renderResearchDelete();
        /* keep the Overview research count honest after a delete */
        Core.loadResearchCount(sessionCreds.endpoint, sessionCreds.adminKey).then(function (rc) {
          state.research = rc;
          renderAll();
        });
      })
      .catch(function (err) {
        researchUi.busy = false;
        researchUi.tone = 'err';
        if (err && err.status === 503) researchUi.message = 'Admin controls are not configured on the server. Set BIOM_ADMIN_KEY in the API project\'s environment variables on Vercel and redeploy — deletion stays off until then (it never fails open).';
        else if (err && err.status === 401) researchUi.message = 'The admin key was refused by the API. Check the admin key in Connection above against BIOM_ADMIN_KEY on the server.';
        else if (err && err.status === 400) researchUi.message = 'The API refused that research code. Check the code exactly as shown on the person\'s device and try again.';
        else if (err && err.body && err.body.error) researchUi.message = 'The API refused: ' + err.body.error + '.';
        else researchUi.message = 'Could not reach the API. Check your connection and try again.';
        renderResearchDelete();
      });
  }

  function lock() {
    sessionCreds = null;
    researchUi = { armed: false, armedCode: '', busy: false, message: '', tone: '' };
    state.scans = [];
    state.profiles = [];
    clearRendered();
    /* v78 (Seat 1): locking clears the Settings form too — a
       password typed there for a save must not sit in the
       hidden DOM behind the lock screen (the v73 rule). */
    els.readKeyInput.value = '';
    els.adminKeyInput.value = '';
    els.passwordInput.value = '';
    els.passwordConfirmInput.value = '';
    showLock(null);
  }

  function init() {
    ['firstRunView', 'settingsView', 'lockView', 'mainView', 'topbarActions', 'endpointChip', 'setupForm', 'endpointInput',
     'readKeyInput', 'adminKeyInput', 'adminKeyState', 'fieldAdminWrap', 'fieldAdminRemoveWrap', 'adminKeyRemoveInput',
     'passwordInput', 'passwordConfirmInput', 'passwordLabel', 'fieldConfirmWrap', 'setupError', 'connectBtn',
     'setupIntroFresh', 'setupIntroMigrate', 'setupIntroManage', 'fieldEndpointWrap', 'fieldKeyWrap',
     'firstRunTextFresh', 'firstRunTextMigrate', 'firstRunSettingsBtn',
     'adminActivityCard', 'adminLogBody', 'blockedIpsBody', 'researchDeleteBody', 'adminLogRefreshBtn', 'settingsBackBtn', 'settingsNavLink', 'bottomSettingsLink',
     'lockForm', 'lockPasswordInput', 'lockError', 'unlockBtn', 'lockResetBtn',
     'errorBanner', 'errorText', 'reenterBtn',
     'statusBanner', 'statusText', 'statsGrid', 'profilesGrid', 'profilesEmpty',
     'kindFilter', 'resultFilter', 'searchInput', 'scanCountLine', 'scansBody',
     'scansEmpty', 'refreshBtn', 'disconnectBtn', 'lockBtn', 'autoRefreshToggle',
     'lastUpdatedLine', 'profileSearchInput', 'profileStatusFilter', 'banksTableBody', 'banksEmpty',
     'recentScansBody', 'recentScansEmpty', 'vaultHealth', 'scansCards', 'bankDrawer', 'bankDrawerBody',
     'bankDrawerCloseBtn', 'viewAllScansBtn', 'sidebarCollapseBtn', 'filterToggleBtn', 'scanFilterBar',
     'overviewSection', 'banksSection', 'scansSection'
    ].forEach(function (id) { els[id] = $(id); });

    /* v78: Settings navigation. From the first-run notice the
       button opens Settings in the pending mode; from inside the
       unlocked dashboard the sidebar/bottom-nav links open it in
       manage mode. While locked (seal exists, no session) the
       links do nothing — the seal cannot be edited without the
       password, by design. Section links return from Settings
       to the main view first. */
    if (els.firstRunSettingsBtn) {
      els.firstRunSettingsBtn.addEventListener('click', function () { showSettings(setupMode); });
    }
    function openSettingsFromNav(ev) {
      ev.preventDefault();
      if (sessionCreds) showSettings('manage');
      else if (!els.settingsView.hidden) { /* already there */ }
      else if (!storedSealed()) showSettings(setupMode);
    }
    if (els.settingsNavLink) els.settingsNavLink.addEventListener('click', openSettingsFromNav);
    if (els.bottomSettingsLink) els.bottomSettingsLink.addEventListener('click', openSettingsFromNav);
    if (els.settingsBackBtn) {
      els.settingsBackBtn.addEventListener('click', function () { showMain(); });
    }
    if (els.adminLogRefreshBtn) {
      els.adminLogRefreshBtn.addEventListener('click', loadAdminLog);
    }
    /* v82: research-delete delegation — arm / confirm / cancel.
       Arm requires a non-empty code; confirm fires the POST only
       for the exact armed code. */
    if (els.researchDeleteBody) {
      els.researchDeleteBody.addEventListener('click', function (ev) {
        var btn = ev.target.closest ? ev.target.closest('[data-action]') : null;
        if (!btn || researchUi.busy) return;
        var action = btn.getAttribute('data-action');
        if (action === 'research-delete-arm') {
          var input = els.researchDeleteBody.querySelector('#researchCodeInput');
          var code = input ? input.value.trim() : '';
          if (!code) {
            researchUi.tone = 'err';
            researchUi.message = 'Enter the research code exactly as shown on the person\'s device first.';
            renderResearchDelete();
            var again = els.researchDeleteBody.querySelector('#researchCodeInput');
            if (again) again.value = '';
            return;
          }
          researchUi.armed = true;
          researchUi.armedCode = code;
          researchUi.message = '';
          renderResearchDelete();
        } else if (action === 'research-delete-cancel') {
          researchUi.armed = false;
          researchUi.message = '';
          renderResearchDelete();
        } else if (action === 'research-delete-confirm') {
          if (!researchUi.armed || !researchUi.armedCode) return;
          runResearchDelete();
        }
      });
    }
    document.querySelectorAll('.side-nav-link:not(#settingsNavLink), .bottom-nav-link:not(#bottomSettingsLink)').forEach(function (link) {
      link.addEventListener('click', function () {
        if (sessionCreds && !els.settingsView.hidden) showMain();
      });
    });

    /* v66 shell wiring: sidebar collapse (memory only), bank
       sorting, the detail drawer, and the mobile filter sheet. */
    if (els.sidebarCollapseBtn) {
      els.sidebarCollapseBtn.addEventListener('click', function () {
        document.body.classList.toggle('sidebar-collapsed');
      });
    }
    if (els.viewAllScansBtn) {
      els.viewAllScansBtn.addEventListener('click', function () {
        if (els.scansSection) els.scansSection.scrollIntoView();
      });
    }
    if (els.filterToggleBtn && els.scanFilterBar) {
      els.filterToggleBtn.addEventListener('click', function () {
        var collapsed = els.scanFilterBar.classList.toggle('filters-collapsed');
        els.filterToggleBtn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
      });
    }
    if (els.profileSearchInput) els.profileSearchInput.addEventListener('input', renderAll);
    if (els.profileStatusFilter) els.profileStatusFilter.addEventListener('change', renderAll);
    document.querySelectorAll('.sort-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var key = btn.getAttribute('data-sort');
        if (state.bankSort.key === key) state.bankSort.dir = state.bankSort.dir * -1;
        else state.bankSort = { key: key, dir: 1 };
        renderAll();
      });
    });
    function openBankDrawer(profile) {
      if (!profile || !els.bankDrawer) return;
      if (drawerUi.biomId !== profile.biomId) {
        drawerUi = { biomId: profile.biomId, armed: false, busy: false, message: '', tone: '' };
      }
      els.bankDrawerBody.innerHTML = Core.renderBankDetailHtml(profile, state.scans) +
        Core.renderPersonControlHtml(profile, state.scans) +
        '<div id="blockActionSlot">' + blockActionHtml(profile) + '</div>';
      els.bankDrawer.hidden = false;
    }

    function blockActionHtml(profile) {
      return Core.renderBlockActionHtml(profile, {
        adminKeyPresent: !!(sessionCreds && sessionCreds.adminKey),
        armed: drawerUi.armed, busy: drawerUi.busy,
        message: drawerUi.message, tone: drawerUi.tone
      }, state.scans);
    }

    function rerenderBlockAction(profile) {
      var slot = document.getElementById('blockActionSlot');
      if (slot) slot.innerHTML = blockActionHtml(profile);
    }

    function adminErrorMessage(err) {
      if (err && err.status === 503) {
        return 'Admin controls are not configured on the server. Set BIOM_ADMIN_KEY in the API project\'s environment variables on Vercel and redeploy — blocking stays off until then (it never fails open).';
      }
      if (err && err.status === 401) {
        return 'The admin key was refused by the API. Check the admin key in Settings → Connection against BIOM_ADMIN_KEY on the server.';
      }
      if (err && err.body && err.body.error) return 'The API refused: ' + err.body.error + '.';
      return 'Could not reach the API. Check your connection and try again.';
    }

    function runAdminAction(profile, action) {
      if (!sessionCreds || !sessionCreds.adminKey || drawerUi.busy) return;
      var reason = '';
      if (action === 'block') {
        var input = els.bankDrawerBody.querySelector('.block-reason-input');
        reason = input ? input.value.trim() : '';
      }
      drawerUi.busy = true;
      drawerUi.message = '';
      rerenderBlockAction(profile);
      var call = action === 'block'
        ? Core.adminBlock(sessionCreds.endpoint, sessionCreds.adminKey, profile.biomId, reason)
        : Core.adminUnblock(sessionCreds.endpoint, sessionCreds.adminKey, profile.biomId);
      call.then(function (res) {
        drawerUi.busy = false;
        drawerUi.armed = false;
        drawerUi.tone = 'ok';
        if (action === 'block') {
          profile.blocked = true;
          profile.blockedTs = Date.now();
          profile.blockedReason = reason || null;
          var revoked = (res && res.revokedDeviceIds) || [];
          drawerUi.message = res && res.already
            ? 'This person was already blocked.'
            : 'Blocked. ' + (revoked.length
              ? 'Devices revoked: ' + revoked.join(', ') + '.'
              : 'No registered device needed revoking.') +
              ' Their sync writes and payments are now refused.';
        } else {
          profile.blocked = false;
          profile.blockedTs = null;
          profile.blockedReason = null;
          drawerUi.message = 'Unblocked. Sync and payments work again — the person\'s devices stay revoked, so they re-register a device to come back.';
        }
        /* v78 (Seat 2 S4): the action applied but its audit-log
           write failed — say so in the same breath, never let a
           clean success hide an unlogged control action. */
        if (res && res.auditWarning) {
          drawerUi.tone = 'err';
          drawerUi.message += ' Warning: ' + res.auditWarning + ' — this action is not in the admin log.';
        }
        renderAll();
        openBankDrawer(profile);
        refresh();
      }).catch(function (err) {
        drawerUi.busy = false;
        drawerUi.tone = 'err';
        drawerUi.message = adminErrorMessage(err);
        rerenderBlockAction(profile);
      });
    }

    if (els.bankDrawerBody) {
      els.bankDrawerBody.addEventListener('click', function (ev) {
        var btn = ev.target.closest ? ev.target.closest('[data-action]') : null;
        if (!btn) return;
        var action = btn.getAttribute('data-action');
        var profile = null;
        state.profiles.forEach(function (p) { if (String(p.biomId || '') === drawerUi.biomId) profile = p; });
        if (!profile) return;
        if (action === 'open-settings') {
          els.bankDrawer.hidden = true;
          showSettings('manage');
        } else if (action === 'block-arm' || action === 'unblock-arm') {
          drawerUi.armed = true; drawerUi.message = '';
          rerenderBlockAction(profile);
        } else if (action === 'block-cancel') {
          drawerUi.armed = false; drawerUi.message = '';
          rerenderBlockAction(profile);
        } else if (action === 'block-confirm') {
          runAdminAction(profile, 'block');
        } else if (action === 'unblock-confirm') {
          runAdminAction(profile, 'unblock');
        }
      });
    }
    if (els.bankDrawerCloseBtn) {
      els.bankDrawerCloseBtn.addEventListener('click', function () { els.bankDrawer.hidden = true; });
    }
    if (els.banksTableBody) {
      els.banksTableBody.addEventListener('click', function (ev) {
        var row = ev.target.closest ? ev.target.closest('tr[data-biom-id]') : null;
        if (!row) return;
        var id = row.getAttribute('data-biom-id');
        var match = null;
        state.profiles.forEach(function (p) { if (String(p.biomId || '') === id) match = p; });
        openBankDrawer(match);
      });
    }
    els.profilesGrid.addEventListener('click', function (ev) {
      var card = ev.target.closest ? ev.target.closest('.profile-card') : null;
      if (!card) return;
      var idx = Array.prototype.indexOf.call(els.profilesGrid.children, card);
      if (idx >= 0 && state.displayedProfiles[idx]) openBankDrawer(state.displayedProfiles[idx]);
    });

    els.setupForm.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var password = els.passwordInput.value;
      var confirm = els.passwordConfirmInput.value;
      var manage = setupMode === 'manage';
      if (!password) {
        els.setupError.textContent = manage
          ? 'Enter your dashboard password — saving re-seals the credentials under it.'
          : 'Set the dashboard password — it seals the read key on this browser.';
        els.setupError.hidden = false;
        return;
      }
      /* v64 (Seat 2 M-6): a minimum length at SETUP and MIGRATION
         only — the seal previously accepted any non-empty string,
         including a one-character password over the read key. The
         unlock path is deliberately NOT length-checked: an existing
         seal must always open with the password it was made with.
         v78: manage mode re-enters the EXISTING password (proven
         by opening the seal), so the floor does not apply there
         either — the password is not being chosen, only proven. */
      if (!manage && password.length < 8) {
        els.setupError.textContent = 'Use at least 8 characters for the dashboard password — it is the only thing protecting the sealed read key on this browser.';
        els.setupError.hidden = false;
        return;
      }
      if (!manage && password !== confirm) {
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
          els.adminKeyInput.value = '';
          showMain();
        });
      };

      if (manage) {
        /* v78 manage: prove the password by opening the current
           seal with it, then re-seal the edited credentials under
           the same password. Blank key fields keep the saved
           values; the remove checkbox clears the admin key. A
           REPLACED read key is verified against the API before
           anything is sealed, so a typo cannot lock the
           dashboard out of its own data. */
        var sealedNow = storedSealed();
        if (!sealedNow || !sessionCreds) { showFirstRun('fresh'); els.connectBtn.disabled = false; return; }
        Core.unsealCredentials(password, sealedNow)
          .then(function (current) {
            var newReadKey = els.readKeyInput.value.trim();
            var creds = {
              endpoint: current.endpoint,
              readKey: newReadKey || current.readKey,
              adminKey: els.adminKeyRemoveInput.checked ? '' : (els.adminKeyInput.value.trim() || current.adminKey || '')
            };
            var verify = newReadKey
              ? Core.loadAll(creds.endpoint, creds.readKey)
              : Promise.resolve(null);
            /* v78 (Seat 1 note): a REPLACED admin key is verified
               against the admin log before it is sealed — a typo
               must surface here, not weeks later at a block. */
            var newAdminKey = els.adminKeyInput.value.trim();
            if (newAdminKey) {
              verify = verify.then(function () {
                return Core.adminLog(creds.endpoint, newAdminKey).catch(function (e) {
                  var ae = new Error('admin key verification failed');
                  ae.adminErr = e;
                  throw ae;
                });
              });
            }
            return verify.then(function () { return finishSetup(creds); });
          })
          .then(function () { refresh(); })
          .catch(function (err) {
            if (err && err.adminErr) {
              els.setupError.textContent = err.adminErr.status === 503
                ? 'Admin controls are not configured on the server (BIOM_ADMIN_KEY is not set), so the new admin key could not be verified. Nothing was changed.'
                : 'The new admin key was refused by the API. Nothing was changed — check the key against BIOM_ADMIN_KEY on the server.';
            } else if (err && err.status === 401) {
              els.setupError.textContent = 'The new read key was refused by the API (unauthorised). Nothing was changed.';
            } else if (err && err.status) {
              els.setupError.textContent = 'The API answered with an error (HTTP ' + err.status + ') while checking the new read key. Nothing was changed.';
            } else if (err && err.message && err.message.indexOf('Seal') !== -1) {
              els.setupError.textContent = 'Could not seal the credentials in this browser. Nothing was changed.';
            } else {
              /* unseal failure = the password did not open the seal */
              els.setupError.textContent = 'That password did not unlock the sealed credentials. Nothing was changed.';
            }
            els.setupError.hidden = false;
          })
          .then(function () { els.connectBtn.disabled = false; });
        return;
      }

      if (setupMode === 'migrate') {
        var legacy = legacyCreds();
        if (!legacy) { showSettings('fresh'); els.connectBtn.disabled = false; return; }
        finishSetup({ endpoint: legacy.endpoint, readKey: legacy.readKey, adminKey: els.adminKeyInput.value.trim() })
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
      var freshAdminKey = els.adminKeyInput.value.trim();
      Core.loadAll(endpoint, readKey)
        .then(function (data) {
          state.scans = data.scans;
          state.profiles = data.profiles;
          /* v78 (Seat 1 note): an admin key entered at setup is
             verified against the admin log before it is sealed. */
          var verifyAdmin = freshAdminKey
            ? Core.adminLog(endpoint, freshAdminKey).catch(function (e) {
              var ae = new Error('admin key verification failed');
              ae.adminErr = e;
              throw ae;
            })
            : Promise.resolve(null);
          return verifyAdmin.then(function () {
            return finishSetup({ endpoint: endpoint, readKey: readKey, adminKey: freshAdminKey });
          });
        })
        /* v82 fix: a fresh connect now refreshes like manage and
           migrate do — previously it only re-rendered the setup-time
           data, so the Research frames card (loaded inside refresh)
           stayed missing until a manual Refresh. */
        .then(function () { refresh(); })
        .catch(function (err) {
          if (err && err.adminErr) {
            els.setupError.textContent = err.adminErr.status === 503
              ? 'Admin controls are not configured on the server (BIOM_ADMIN_KEY is not set), so the admin key could not be verified. Nothing was saved — leave the admin key blank to connect without blocking, or set BIOM_ADMIN_KEY first.'
              : 'The admin key was refused by the API. Nothing was saved — check it against BIOM_ADMIN_KEY on the server, or leave it blank to connect without blocking.';
          } else if (err && err.status === 401) {
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
      if (!sealed) { showFirstRun('fresh'); return; }
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
      showFirstRun('fresh');
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

    /* v63 entry rule, v78 shape: a sealed browser goes to the
       LOCK screen (password only) and fetches nothing until the
       password unlocks it; a browser with no seal gets the quiet
       first-run notice — fresh, or the migration variant when a
       pre-v63 plaintext key is still held. The setup form itself
       lives only in Settings and never fronts the dashboard. */
    if (storedSealed()) {
      showLock(null);
    } else if (legacyCreds()) {
      showFirstRun('migrate');
    } else {
      showFirstRun('fresh');
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
