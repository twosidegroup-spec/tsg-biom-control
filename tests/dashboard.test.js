/* TSG Biom Control — dashboard checks (v62: the summary switch;
   v63: the password-only login).

   Proves, headlessly against the exact Core the page ships:
   - loadAll fetches profiles ONLY from the summary endpoint
     (never the full-bank list), so rendering counts costs no
     template downloads;
   - the profile cards render from summary-shaped data (counts,
     version, encryption state, owner device) — the fixtures
     carry no template strings at all;
   - a tombstoned bank renders as a Removed card with its
     deletion time, and the Enrolled profiles stat counts live
     banks only;
   - the read key rides the header and appears in no URL;
   - v63: the credential seal round-trips under a password
     (AES-GCM / PBKDF2), a wrong password is refused, the sealed
     record holds no readable credential, the shipped wiring
     keeps credentials in memory only (no plaintext write path
     remains), and the lock screen gates the data — the page
     markup carries a password-only lock form and the wiring
     fetches only behind the in-memory session credentials.
   Run: npm test */
'use strict';
const fs = require('fs');
const path = require('path');
const Core = require('../app.js');

let pass = 0, fail = 0;
function check(name, cond, detail) {
  if (cond) { pass++; console.log('  ok  ' + name + (detail ? '  [' + detail + ']' : '')); }
  else { fail++; console.log('FAIL  ' + name + (detail ? '  [' + detail + ']' : '')); }
}

const SUMMARY = [
  { biomId: 'TSG-BIO-2841', name: 'Sajid', hand: 'left', neuralModel: 'palmnet-r3-ep12', edccCount: 3, neuralCount: 3, enc: 'v1', version: 4, deleted: false, deletedTs: null, updatedTs: 1764000000000, ownerDeviceId: 'dev-abc123' },
  { biomId: 'TSG-BIO-7777', name: 'Old Bank', hand: 'right', neuralModel: '', edccCount: 0, neuralCount: 0, enc: null, version: 2, deleted: true, deletedTs: 1764100000000, updatedTs: 1764100000000, ownerDeviceId: 'legacy' }
];
const SCANS = [
  { id: 's1', ts: 1764000000000, deviceLabel: 'Rig', kind: 'verify', profileName: 'Sajid', biomId: 'TSG-BIO-2841', hand: 'left', edccScore: 0.5, palmnetScore: 0.9, result: 'Verified', modelId: 'palmnet-r3-ep12', appVersion: 'v62' }
];

async function main() {
  const calls = [];
  const fetchFn = function (url, opts) {
    calls.push({ url: url, headers: opts.headers });
    const body = url.indexOf('/api/scans') !== -1 ? { ok: true, count: SCANS.length, scans: SCANS }
      : { ok: true, count: SUMMARY.length, profiles: SUMMARY };
    return Promise.resolve({ status: 200, ok: true, json: function () { return Promise.resolve(body); } });
  };
  const data = await Core.loadAll('https://api.test/', 'read-key-1', fetchFn);
  check('LOAD loadAll returns the scans and the profile summaries',
    data.scans.length === 1 && data.profiles.length === 2);
  const profileCall = calls.filter(function (c) { return c.url.indexOf('/api/profiles') !== -1; })[0];
  check('LOAD profiles come from the SUMMARY endpoint, never the full-bank list',
    !!profileCall && profileCall.url === 'https://api.test/api/profiles?summary=1', profileCall && profileCall.url);
  check('LOAD the read key rides the header and appears in no URL',
    calls.every(function (c) { return c.headers['x-read-key'] === 'read-key-1' && c.url.indexOf('read-key-1') === -1; }));

  const html = Core.renderProfilesHtml(data.profiles);
  check('RENDER the live card shows counts from the summary (no template arrays involved)',
    html.indexOf('TSG-BIO-2841') !== -1 && html.indexOf('<dt>EDCC templates</dt><dd>3</dd>') !== -1 &&
    html.indexOf('<dt>PalmNet embeddings</dt><dd>3</dd>') !== -1);
  check('RENDER the live card shows version, encryption state and owner device',
    html.indexOf('<dt>Version</dt><dd>4</dd>') !== -1 && html.indexOf('Sealed (enc v1)') !== -1 &&
    html.indexOf('dev-abc123') !== -1);
  check('RENDER the tombstoned bank renders as a Removed card with its deletion time',
    html.indexOf('Removed') !== -1 && html.indexOf('TSG-BIO-7777') !== -1 && html.indexOf('Deleted (tombstone)') !== -1);
  check('RENDER no fixture carried template strings, yet everything rendered (proof the summary suffices)',
    JSON.stringify(SUMMARY).indexOf('edccCodes') === -1 && html.length > 200);

  const stats = Core.computeStats(data.scans, data.profiles);
  check('STATS the Enrolled profiles stat counts LIVE banks only (tombstone excluded)',
    stats.profiles === 1 && stats.totalScans === 1 && stats.verified === 1, 'profiles=' + stats.profiles);
  const statsHtml = Core.renderStatsHtml(stats);
  check('STATS the stats strip renders from the same data', statsHtml.indexOf('Enrolled profiles') !== -1);

  const src = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');
  check('SOURCE the dashboard never fetches the bare full-bank list',
    src.indexOf("'/api/profiles'") === -1 && src.indexOf("'/api/profiles?summary=1'") !== -1);

  /* ---------- v63: the password seal ---------- */
  const TEST_PASSWORD = 'test-password-63';
  const creds = { endpoint: 'https://api.test', readKey: 'read-key-xyz-123' };
  const sealed = await Core.sealCredentials(TEST_PASSWORD, creds);
  check('SEAL the sealed record is versioned base64 parts, PBKDF2 at 600k iterations',
    sealed.v === 1 && sealed.iter === 600000 && typeof sealed.salt === 'string' &&
    typeof sealed.iv === 'string' && typeof sealed.ct === 'string');
  check('SEAL the sealed record holds NO readable credential',
    JSON.stringify(sealed).indexOf(creds.readKey) === -1 &&
    JSON.stringify(sealed).indexOf(creds.endpoint) === -1 &&
    Buffer.from(sealed.ct, 'base64').toString('utf8').indexOf(creds.readKey) === -1);
  const opened = await Core.unsealCredentials(TEST_PASSWORD, sealed);
  check('SEAL the correct password opens the seal and returns the credentials',
    opened.endpoint === creds.endpoint && opened.readKey === creds.readKey);
  let wrongRejected = false;
  try { await Core.unsealCredentials('not-the-password', sealed); } catch (e) { wrongRejected = true; }
  check('SEAL a wrong password is refused (the seal integrity check fails, nothing opens)',
    wrongRejected);
  const sealed2 = await Core.sealCredentials(TEST_PASSWORD, creds);
  check('SEAL every seal is fresh (random salt/IV — two seals of one key differ)',
    sealed2.ct !== sealed.ct && sealed2.salt !== sealed.salt);

  /* ---------- v63: the lock gate in the shipped wiring ---------- */
  const pageHtml = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
  const lockSlice = pageHtml.slice(pageHtml.indexOf('id="lockView"'), pageHtml.indexOf('id="setupView"'));
  check('LOCK the lock screen asks ONLY for the password (no read-key or endpoint field)',
    lockSlice.indexOf('id="lockPasswordInput"') !== -1 && lockSlice.indexOf('type="password"') !== -1 &&
    lockSlice.indexOf('readKeyInput') === -1 && lockSlice.indexOf('endpointInput') === -1);
  check('LOCK credentials live in memory only — refresh is gated on the session credentials',
    src.indexOf('var sessionCreds = null;') !== -1 &&
    src.indexOf('var creds = sessionCreds;') !== -1 &&
    src.indexOf('if (!creds || state.loading) return Promise.resolve();') !== -1);
  check('LOCK a sealed browser boots to the lock screen before any fetch path runs',
    src.indexOf('if (storedSealed()) {') !== -1 && src.indexOf('showLock(null);') !== -1);
  check('LOCK no plaintext write path remains: the read key is never setItem-ed, only the sealed record is',
    src.indexOf('setItem(LS_READ_KEY') === -1 && src.indexOf('setItem(LS_ENDPOINT') === -1 &&
    src.indexOf('setItem(LS_SEALED') !== -1 && src.indexOf("var LS_SEALED = 'tsgBiomControl.sealed';") !== -1);
  check('LOCK the legacy plaintext entries are removed once the seal is written (migration)',
    src.indexOf('removeItem(LS_READ_KEY)') !== -1 && src.indexOf("setupMode === 'migrate'") !== -1);
  check('LOCK no credential or password literal is embedded in the shipped files',
    src.indexOf('read-key-xyz-123') === -1 && pageHtml.indexOf('read-key-xyz-123') === -1 &&
    !/(^|[^A-Z_])READ_KEY\s*=\s*['"][^'"]+['"]/.test(src) &&
    /* the password is verified by the seal, never compared
       against a literal in the code */
    src.indexOf('password ===') === -1 && src.indexOf('value === \'') === -1 &&
    src.indexOf('Core.unsealCredentials(') !== -1);

  /* ---------- v64: CSP, escaping proof, password floor, polish --- */
  const cspMatch = pageHtml.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/);
  check('V64 the dashboard ships a Content-Security-Policy meta (Pages cannot send headers — the README states the limits)',
    !!cspMatch && cspMatch[1].indexOf("default-src 'none'") === 0);
  check('V64 the policy allows scripts from self only — no unsafe-inline, no CDN',
    !!cspMatch && cspMatch[1].indexOf("script-src 'self'") !== -1 &&
    cspMatch[1].indexOf('unsafe-inline') === -1 && cspMatch[1].indexOf('http') === cspMatch[1].indexOf('https://tsg-biom-api.vercel.app'));
  check('V64 connect-src is pinned to the one TSG Biom API this build talks to',
    !!cspMatch && cspMatch[1].indexOf('connect-src https://tsg-biom-api.vercel.app') !== -1);
  check('V64 the page sends no referrer', pageHtml.indexOf('<meta name="referrer" content="no-referrer">') !== -1);

  /* The hostile-fixture proof (Seat 2 re-verification, executable):
     a profile name and scan fields carrying markup must render as
     TEXT through the shipped Core renderers — the escaped entity
     present, the raw tag absent. */
  const hostile = [{
    biomId: 'TSG-BIO-6666', name: '<script>alert(1)</script>', hand: 'left', neuralModel: 'palmnet-r3-ep12',
    edccCount: 1, neuralCount: 1, enc: 'v1', version: 1, deleted: false, deletedTs: null,
    updatedTs: 1764000000000, ownerDeviceId: 'dev-<img src=x onerror=alert(2)>'
  }];
  const hostileHtml = Core.renderProfilesHtml(hostile);
  check('V64 ESCAPING a hostile profile name renders as text, never markup',
    hostileHtml.indexOf('&lt;script&gt;alert(1)&lt;/script&gt;') !== -1 &&
    hostileHtml.indexOf('<script>alert(1)</script>') === -1 &&
    hostileHtml.indexOf('<img src=x') === -1);
  const hostileScans = [{
    id: 'sx', ts: 1764000000000, deviceLabel: '<b>Rig</b>', kind: 'verify',
    profileName: '"><svg onload=alert(3)>', biomId: 'TSG-BIO-6666', hand: 'left',
    edccScore: 0.5, palmnetScore: 0.9, result: 'Verified'
  }];
  const hostileRows = Core.renderScansRowsHtml(hostileScans);
  check('V64 ESCAPING hostile scan fields render as text, never markup',
    hostileRows.indexOf('<svg onload') === -1 && hostileRows.indexOf('<b>Rig</b>') === -1 &&
    hostileRows.indexOf('&lt;b&gt;Rig&lt;/b&gt;') !== -1 && hostileRows.indexOf('&lt;svg') !== -1);

  check('V64 the setup/migration password floor is 8 characters, with the honest reason in the copy',
    src.indexOf('password.length < 8') !== -1 &&
    src.indexOf('at least 8 characters for the dashboard password') !== -1);
  const lockSubmit = src.slice(src.indexOf("els.lockForm.addEventListener('submit'"));
  check('V64 the UNLOCK path carries NO length check (an existing seal always opens with its own password)',
    lockSubmit.indexOf('password.length') === -1 && lockSubmit.indexOf('unsealCredentials') !== -1);

  const dashCss = fs.readFileSync(path.join(__dirname, '..', 'styles.css'), 'utf8');
  check('V64 the topbar is the solid house colour (no gradient) and linklike names a defined token',
    dashCss.indexOf('linear-gradient') === -1 && dashCss.indexOf('color:var(--blue-600)') !== -1);
  check('V64 cold-load skeletons exist in wiring + CSS, and the count line is a polite live region',
    src.indexOf('skelstat') !== -1 && src.indexOf('skelcard') !== -1 &&
    dashCss.indexOf('.skelbar') !== -1 && pageHtml.indexOf('id="scanCountLine" aria-live="polite"') !== -1);
  check('V64 buttons meet the 44px floor and keyboard focus is visible',
    dashCss.indexOf('min-height: 44px') !== -1 && dashCss.indexOf(':focus-visible') !== -1);


  /* ---------- v66: House System v2 + adaptive shell ---------- */
  check('V66 the desktop shell is a sidebar with brand, job-named destinations and a session block',
    pageHtml.indexOf('id="sidebar"') !== -1 && pageHtml.indexOf('>Overview<') !== -1 &&
    pageHtml.indexOf('>Palm Banks<') !== -1 && pageHtml.indexOf('>Scan Log<') !== -1 &&
    pageHtml.indexOf('id="endpointChip"') !== -1 && pageHtml.indexOf('id="lockBtn"') !== -1);
  check('V66 the sidebar has a collapse control and the collapse state is memory-only (no storage write for it)',
    pageHtml.indexOf('id="sidebarCollapseBtn"') !== -1 && src.indexOf("classList.toggle('sidebar-collapsed')") !== -1 &&
    src.indexOf("setItem('sidebar") === -1 && src.indexOf('setItem("sidebar') === -1);
  check('V66 mobile gets a bottom nav with the three destinations and no sidebar dependency',
    pageHtml.indexOf('class="bottom-nav"') !== -1 && pageHtml.indexOf('>Banks<') !== -1 &&
    pageHtml.indexOf('>Scans<') !== -1 && dashCss.indexOf('.bottom-nav') !== -1);
  check('V66 the existing scan search is promoted into the shell top bar with a last-updated line',
    pageHtml.indexOf('class="shell-topbar"') !== -1 &&
    pageHtml.slice(pageHtml.indexOf('class="shell-topbar"'), pageHtml.indexOf('id="errorBanner"')).indexOf('id="searchInput"') !== -1 &&
    pageHtml.indexOf('id="lastUpdatedLine"') !== -1);
  check('V66 Palm Banks is table-first on desktop: sortable columns, a toolbar search + status filter, and a detail drawer',
    pageHtml.indexOf('id="banksTableBody"') !== -1 && pageHtml.indexOf('data-sort="biomId"') !== -1 &&
    pageHtml.indexOf('data-sort="edccCount"') !== -1 && pageHtml.indexOf('data-sort="neuralCount"') !== -1 &&
    pageHtml.indexOf('data-sort="status"') !== -1 && pageHtml.indexOf('id="profileSearchInput"') !== -1 &&
    pageHtml.indexOf('id="profileStatusFilter"') !== -1 && pageHtml.indexOf('id="bankDrawer"') !== -1 &&
    pageHtml.indexOf('id="bankDrawerBody"') !== -1);
  const banksRows = Core.renderBanksRowsHtml(data.profiles);
  check('V66 the banks table renders summary counts and status (incl. Removed) with no template data',
    banksRows.indexOf('TSG-BIO-2841') !== -1 && banksRows.indexOf('>3</td>') !== -1 &&
    banksRows.indexOf('Removed') !== -1 && banksRows.indexOf('data-biom-id="TSG-BIO-7777"') !== -1);
  /* v74 supersedes the v66 equality below: the Chairman's
     extension orders the person detail to ADD the registration
     record + scan history to the same summary card. The
     summary-only rule still holds — the detail renders from the
     summary record plus already-loaded scan summaries only. */
  check('V66/V74 the drawer detail opens with the same summary card the grid renders (summary-only rule intact), then the v74 sections',
    Core.renderBankDetailHtml(data.profiles[0]).indexOf(Core.renderProfilesHtml([data.profiles[0]])) === 0 &&
    Core.renderBankDetailHtml(data.profiles[0]).indexOf('Sealed (enc v1)') !== -1 &&
    Core.renderBankDetailHtml(data.profiles[0]).indexOf('Registration record') !== -1);
  check('V66 bank sorting orders by the chosen summary column',
    Core.sortProfiles(data.profiles, 'version', 1)[0].biomId === 'TSG-BIO-7777' &&
    Core.sortProfiles(data.profiles, 'version', -1)[0].biomId === 'TSG-BIO-2841');
  check('V66 Overview panels render from existing data only: recent scans capped at 8 and vault health summary',
    Core.renderRecentScansRowsHtml(data.scans).indexOf('TSG-BIO-2841') !== -1 &&
    Core.renderVaultHealthHtml(data.profiles).indexOf('Removed (tombstones)') !== -1 &&
    Core.renderVaultHealthHtml(data.profiles).indexOf('sealed (enc v1)') !== -1 &&
    pageHtml.indexOf('id="recentScansBody"') !== -1 && pageHtml.indexOf('id="vaultHealth"') !== -1 &&
    pageHtml.indexOf('id="viewAllScansBtn"') !== -1);
  check('V66 the mobile scan cards are day-grouped with the verdict chip first',
    Core.renderScanCardsHtml(data.scans).indexOf('scan-day') !== -1 &&
    Core.renderScanCardsHtml(data.scans).indexOf('badge badge-verified') !== -1 &&
    pageHtml.indexOf('id="scansCards"') !== -1 && pageHtml.indexOf('id="filterToggleBtn"') !== -1);
  check('V66 tokens have a SINGLE source (one :root block) and every figure style uses tabular numerals',
    (dashCss.match(/:root\s*\{/g) || []).length === 1 &&
    dashCss.indexOf('font-variant-numeric: tabular-nums') !== -1 &&
    dashCss.indexOf('--primary:  #0b4ea2') !== -1 && dashCss.indexOf('--blue-950: #071c3f') !== -1 &&
    dashCss.indexOf('--radius-sm: 12px') !== -1 && dashCss.indexOf('--radius-lg: 20px') !== -1 &&
    dashCss.indexOf('--row-height: 44px') !== -1);
  check('V66 skeletons exist in the new layouts (table-row skeletons desktop, card skeletons mobile)',
    src.indexOf('skeltrow') !== -1 && dashCss.indexOf('.skeltrow') !== -1 &&
    src.indexOf('skelcard') !== -1 && src.indexOf('skelstat') !== -1);
  check('V66 the reduced-motion block covers the new drawer and sidebar transitions',
    dashCss.indexOf('prefers-reduced-motion: reduce') !== -1 &&
    dashCss.indexOf('.drawer') !== -1 && dashCss.indexOf('transition: transform var(--motion-page)') !== -1 &&
    dashCss.indexOf('transition: width var(--motion-page)') !== -1);
  check('V66 lock and setup use the split brand-panel layout and the setup fields are unchanged',
    pageHtml.indexOf('class="auth-split"') !== -1 && pageHtml.indexOf('class="auth-brand"') !== -1 &&
    pageHtml.indexOf('id="endpointInput"') !== -1 && pageHtml.indexOf('id="readKeyInput"') !== -1 &&
    pageHtml.indexOf('id="passwordInput"') !== -1 && pageHtml.indexOf('id="passwordConfirmInput"') !== -1);
  const vercel = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'vercel.json'), 'utf8'));
  const vHead = (vercel.headers && vercel.headers[0]) || {};
  const vMap = {};
  (vHead.headers || []).forEach(function (h) { vMap[h.key] = h.value; });
  check('V66 vercel.json adds the response headers Pages could never send, for all paths',
    vHead.source === '/(.*)' && vMap['X-Frame-Options'] === 'DENY' &&
    vMap['Referrer-Policy'] === 'no-referrer' &&
    vMap['Permissions-Policy'] === 'camera=(), microphone=(), geolocation=()');
  check('V66 render-gate fix: the hidden attribute always wins over view layout display values ([hidden] guard present)',
    dashCss.indexOf('[hidden] { display: none !important; }') !== -1);
  check('V66 render-gate fix: overview panels cannot blow out the page width (minmax(0,...) tracks, panels min-width 0, table wraps scroll internally)',
    dashCss.indexOf('grid-template-columns: minmax(0, 1fr)') !== -1 &&
    dashCss.indexOf('grid-template-columns: minmax(0, 7fr) minmax(0, 5fr)') !== -1 &&
    dashCss.indexOf('.panel { min-width: 0; }') !== -1 &&
    dashCss.indexOf('overflow-x: auto') !== -1);
  check('V66 seal mechanics remain pinned by the v63 checks above and the scan table keeps its columns (no invented writer column)',
    pageHtml.indexOf('<th scope="col">Device</th>') !== -1 && pageHtml.indexOf('Writer') === -1 &&
    typeof Core.sealCredentials === 'function' && Core.PBKDF2_ITERATIONS === 600000);

  /* ---- v74: scan durations, the over-2s flag, person detail ---- */
  check('V74 fmtDuration renders tenths from the real milliseconds',
    Core.fmtDuration(1834.6) === '1.8s' && Core.fmtDuration(2000) === '2.0s' && Core.fmtDuration(0) === '0.0s');
  check('V74 fmtDuration shows Unmeasured for a missing or invalid duration — never an estimate',
    Core.fmtDuration(undefined) === 'Unmeasured' && Core.fmtDuration(null) === 'Unmeasured' &&
    Core.fmtDuration(-1) === 'Unmeasured' && Core.fmtDuration('fast') === 'Unmeasured');
  check('V74 the slow flag is decided on raw milliseconds (2,049 ms flags even though it displays 2.0s; exactly 2,000 ms does not)',
    Core.isSlowScan({ durationMs: 2049 }) === true && Core.fmtDuration(2049) === '2.0s' &&
    Core.isSlowScan({ durationMs: 2000 }) === false && Core.isSlowScan({}) === false);
  const durScans = [
    { id: 'd1', ts: 1764000100000, deviceLabel: 'Rig', kind: 'money-auth', profileName: 'Sajid', biomId: 'TSG-BIO-2841', hand: 'left', edccScore: 0.5, palmnetScore: 0.9, result: 'Verified', durationMs: 1712 },
    { id: 'd2', ts: 1764000200000, deviceLabel: 'Rig', kind: 'verify', profileName: 'Sajid', biomId: 'TSG-BIO-2841', hand: 'left', edccScore: 0.5, palmnetScore: 0.9, result: 'Verified', durationMs: 2600 },
    { id: 'd3', ts: 1764000300000, deviceLabel: 'Rig', kind: 'enrol', profileName: 'Sajid', biomId: 'TSG-BIO-2841', hand: 'left', edccScore: null, palmnetScore: null, result: 'Enrolled' },
    { id: 'd4', ts: 1764000400000, deviceLabel: 'Rig', kind: 'verify', profileName: 'Other', biomId: 'TSG-BIO-9999', hand: 'right', edccScore: 0.4, palmnetScore: 0.8, result: 'Verified', durationMs: 900 }
  ];
  const durRows = Core.renderScansRowsHtml(durScans);
  check('V74 the Scan Log rows carry a Duration cell with the measured value',
    durRows.indexOf('data-label="Duration"') !== -1 && durRows.indexOf('1.7s') !== -1 && durRows.indexOf('2.6s') !== -1);
  check('V74 a scan over 2.0s is visibly flagged in the Scan Log',
    durRows.indexOf('duration-slow') !== -1 && durRows.indexOf('Over 2s') !== -1);
  check('V74 an unmeasured scan shows Unmeasured in the Scan Log, unflagged',
    durRows.indexOf('Unmeasured') !== -1 && (durRows.match(/Over 2s/g) || []).length === 1);
  check('V74 the Scan Log table header carries the Duration column',
    pageHtml.indexOf('<th scope="col">Duration</th>') !== -1);
  const durCards = Core.renderScanCardsHtml(durScans);
  check('V74 the mobile scan cards carry the duration and the flag',
    durCards.indexOf('Duration') !== -1 && durCards.indexOf('2.6s') !== -1 && durCards.indexOf('Over 2s') !== -1);
  const detailProfile = { biomId: 'TSG-BIO-2841', name: 'Sajid', phone: '01933038706', hand: 'left', neuralModel: 'palmnet-r3-ep12', edccCount: 3, neuralCount: 3, enc: 'v1', version: 4, deleted: false, deletedTs: null, updatedTs: 1764000000000, ownerDeviceId: 'dev-abc123' };
  const detail = Core.renderBankDetailHtml(detailProfile, durScans);
  check('V74 the person detail shows the registration record: name, phone, palm registered',
    detail.indexOf('Registration record') !== -1 && detail.indexOf('01933038706') !== -1 &&
    detail.indexOf('Left palm registered') !== -1 && detail.indexOf('3 EDCC') !== -1);
  check('V74 the person detail scan history lists only that person\'s scans, with durations and the flag',
    detail.indexOf('Scan history') !== -1 && detail.indexOf('1.7s') !== -1 && detail.indexOf('2.6s') !== -1 &&
    detail.indexOf('Unmeasured') !== -1 && detail.indexOf('Over 2s') !== -1 && detail.indexOf('0.9s') === -1);
  const detailNoPhone = Core.renderBankDetailHtml({ biomId: 'TSG-BIO-2841', name: 'Sajid', hand: 'left', edccCount: 1, neuralCount: 0, deleted: false }, []);
  check('V74 a legacy profile without a phone renders the detail with an em dash and an empty history note',
    detailNoPhone.indexOf('Registration record') !== -1 && detailNoPhone.indexOf('No scans recorded for this person yet.') !== -1);
  const dashAppSrc = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');
  check('V74 the drawer wiring passes the loaded scans into the person detail',
    dashAppSrc.indexOf('Core.renderBankDetailHtml(profile, state.scans)') !== -1);

  console.log('\n' + (fail === 0 ? 'ALL DASHBOARD TESTS PASSED (' + pass + ')' : fail + ' FAILURES, ' + pass + ' passed'));
  process.exit(fail === 0 ? 0 : 1);
}

main().catch(function (e) { console.error(e); process.exit(1); });
