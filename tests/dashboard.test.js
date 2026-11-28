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
  const lockSlice = pageHtml.slice(pageHtml.indexOf('id="lockView"'), pageHtml.indexOf('id="firstRunView"'));
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

  /* ---- v78: Settings-page connection, first-run front door ---- */
  check('V78 the front door with no seal is a quiet notice — the first-run view holds NO form fields at all',
    pageHtml.indexOf('id="firstRunView"') !== -1 &&
    pageHtml.slice(pageHtml.indexOf('id="firstRunView"'), pageHtml.indexOf('id="settingsView"')).indexOf('<input') === -1 &&
    pageHtml.slice(pageHtml.indexOf('id="firstRunView"'), pageHtml.indexOf('id="settingsView"')).indexOf('id="firstRunSettingsBtn"') !== -1);
  check('V78 the connection form lives INSIDE the Settings view (endpoint, read key, admin key, password)',
    pageHtml.indexOf('id="settingsView"') !== -1 &&
    pageHtml.indexOf('id="setupForm"') > pageHtml.indexOf('id="settingsView"') &&
    pageHtml.indexOf('id="adminKeyInput"') > pageHtml.indexOf('id="settingsView"') &&
    pageHtml.indexOf('id="adminActivityCard"') > pageHtml.indexOf('id="settingsView"'));
  check('V78 Settings is reachable from the sidebar and the mobile bottom nav',
    pageHtml.indexOf('id="settingsNavLink"') !== -1 && pageHtml.indexOf('id="bottomSettingsLink"') !== -1 &&
    pageHtml.indexOf('id="settingsBackBtn"') !== -1);
  check('V78 entry rule: sealed -> lock; legacy -> first-run migrate notice; new -> first-run notice (setup never fronts)',
    dashAppSrc.indexOf("showFirstRun('migrate')") !== -1 && dashAppSrc.indexOf("showFirstRun('fresh')") !== -1 &&
    dashAppSrc.indexOf('showSetup(') === -1 && dashAppSrc.indexOf('id="setupView"') === -1 &&
    pageHtml.indexOf('id="setupView"') === -1);
  const sealedAdmin = await Core.sealCredentials(TEST_PASSWORD, { endpoint: 'https://api.test', readKey: 'rk-1', adminKey: 'ak-1' });
  const openedAdmin = await Core.unsealCredentials(TEST_PASSWORD, sealedAdmin);
  check('V78 the admin key rides the SAME seal as the read key and round-trips under the password',
    openedAdmin.adminKey === 'ak-1' && openedAdmin.readKey === 'rk-1' &&
    JSON.stringify(sealedAdmin).indexOf('ak-1') === -1);
  check('V78 a pre-v78 seal (no adminKey in the payload) opens with an empty admin key',
    dashAppSrc.indexOf("adminKey: obj.adminKey || ''") !== -1);

  /* ---- v78: person control view (network, palm code, wallet) ---- */
  const FP = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';
  const FULL = [{
    biomId: 'TSG-BIO-2841', name: 'Sajid', phone: '01933038706', hand: 'left', neuralModel: 'palmnet-r3-ep12',
    edccCount: 3, neuralCount: 3, enc: 'v1', version: 5, deleted: false, deletedTs: null,
    createdTs: 1763900000000, updatedTs: 1764200000000, ownerDeviceId: 'dev-abc123',
    blocked: false, blockedTs: null, blockedReason: null,
    regIp: '203.0.113.7', regGeoCountry: 'BD', regGeoCity: 'Dhaka',
    lastIp: '198.51.100.9', lastGeoCountry: 'BD', lastGeoCity: 'Chattogram',
    bankFingerprint: FP, edccBytes: 2560, neuralDims: 512,
    wallet: { balance: 1500, statement: [
      { ref: 'w1', ts: 1764000000000, kind: 'add', amount: 2000, balanceAfter: 2000, accountType: 'bkash', accountLabel: 'bKash ••8575' },
      { ref: 'w2', ts: 1764100000000, kind: 'send', amount: 500, balanceAfter: 1500, counterpartyId: 'TSG-BIO-5555', counterpartyName: 'Rahim Uddin' },
      { ref: 'w3', ts: 1764150000000, kind: 'receive', amount: 250, balanceAfter: 1750, counterpartyId: 'TSG-BIO-5555', counterpartyName: 'Rahim Uddin' },
      { ref: 'w4', ts: 1764180000000, kind: 'send', amount: 250, balanceAfter: 1500, counterpartyId: 'TSG-BIO-5555', counterpartyName: 'Rahim Uddin' }
    ] },
    pays: [ { id: 'BIOM-PAY-1', ts: 1764190000000, amount: 300, store: 'Test Store', provider: 'bkash', status: 'Completed' } ]
  }];
  const NET_SCANS = [
    { id: 'n1', ts: 1764300000000, deviceLabel: 'Rig', kind: 'verify', profileName: 'Sajid', biomId: 'TSG-BIO-2841', hand: 'left', edccScore: 0.5, palmnetScore: 0.9, result: 'Verified', ip: '192.0.2.44', geoCountry: 'BD', geoCity: 'Khulna' }
  ];
  const control = Core.renderPersonControlHtml(FULL[0], NET_SCANS);
  check('V78 the person view shows registration IP + location from the server stamps',
    control.indexOf('Registered from') !== -1 && control.indexOf('203.0.113.7') !== -1 && control.indexOf('Dhaka, BD') !== -1);
  check('V78 the latest sighting is the NEWER scan stamp, not the older profile stamp',
    control.indexOf('Latest seen') !== -1 && control.indexOf('192.0.2.44') !== -1 && control.indexOf('Khulna, BD') !== -1);
  check('V78 the palm renders as CODE: envelope, template counts/sizes and the SHA-256 fingerprint — never an image',
    control.indexOf('Palm — encrypted code') !== -1 && control.indexOf('enc.v1 (sealed)') !== -1 &&
    control.indexOf(FP) !== -1 && control.indexOf('2560 bytes') !== -1 && control.indexOf('512 dimensions') !== -1 &&
    control.indexOf('<img') === -1 && control.indexOf('no palm image exists') !== -1);
  const totals = Core.walletTotals(FULL[0]);
  check('V78 wallet totals derive exactly like the app statement (added/sent/received/paid + balance)',
    totals.balance === 1500 && totals.added === 2000 && totals.sent === 750 && totals.received === 250 && totals.paid === 300,
    JSON.stringify(totals));
  check('V78 the ledger lists every entry kind with its counterparty / merchant detail',
    control.indexOf('BDT 1,500') !== -1 && control.indexOf('Add money') !== -1 && control.indexOf('bKash ••8575') !== -1 &&
    control.indexOf('Send money → Rahim Uddin (TSG-BIO-5555)') !== -1 && control.indexOf('Received ← Rahim Uddin') !== -1 &&
    control.indexOf('Biom Pay · Test Store · bkash') !== -1 && control.indexOf('Total paid (Biom Pay)') !== -1);
  const legacyControl = Core.renderPersonControlHtml(SUMMARY[0], SCANS);
  check('V78 a pre-v78 summary degrades honestly (capture/fingerprint/wallet notes, no invented values)',
    legacyControl.indexOf('Not captured') !== -1 && legacyControl.indexOf('fingerprint appears here once the API runs the v78 build') !== -1 &&
    legacyControl.indexOf('Wallet records appear here') !== -1 && legacyControl.indexOf('BDT') === -1);
  check('V78 a tombstone renders no control sections at all',
    Core.renderPersonControlHtml(SUMMARY[1], SCANS) === '');
  const hostileControl = Core.renderPersonControlHtml({ biomId: 'X', name: 'n', deleted: false, wallet: { balance: 5, statement: [{ ref: 'h', ts: 1, kind: 'send', amount: 5, balanceAfter: 0, counterpartyId: 'Y', counterpartyName: '<script>alert(9)</script>' }] } }, []);
  check('V78 ESCAPING a hostile counterparty name in the ledger renders as text',
    hostileControl.indexOf('<script>alert(9)</script>') === -1 && hostileControl.indexOf('&lt;script&gt;') !== -1);

  /* ---- v78: block flow states + admin API ---- */
  const noKeyHtml = Core.renderBlockActionHtml(FULL[0], { adminKeyPresent: false });
  check('V78 BLOCK with no admin key sealed, the control explains and routes to Settings',
    noKeyHtml.indexOf('not set up on this browser') !== -1 && noKeyHtml.indexOf('data-action="open-settings"') !== -1 &&
    noKeyHtml.indexOf('data-action="block-arm"') === -1);
  const armHtml = Core.renderBlockActionHtml(FULL[0], { adminKeyPresent: true });
  check('V78 BLOCK an unblocked person gets the block action with the enforcement copy',
    armHtml.indexOf('data-action="block-arm"') !== -1 && armHtml.indexOf('revokes the person') !== -1 &&
    armHtml.indexOf('This account has been blocked') !== -1);
  const armedHtml = Core.renderBlockActionHtml(FULL[0], { adminKeyPresent: true, armed: true });
  check('V78 BLOCK the armed state asks for an optional reason and a confirm tap (two-tap rule)',
    armedHtml.indexOf('block-reason-input') !== -1 && armedHtml.indexOf('data-action="block-confirm"') !== -1 &&
    armedHtml.indexOf('data-action="block-cancel"') !== -1);
  const blockedHtml = Core.renderBlockActionHtml({ biomId: 'B', deleted: false, blocked: true, blockedTs: 1764200000000, blockedReason: 'Chargeback abuse' }, { adminKeyPresent: true });
  check('V78 BLOCK a blocked person shows the badge, when + why, and the devices-stay-revoked unblock copy',
    blockedHtml.indexOf('Blocked') !== -1 && blockedHtml.indexOf('Chargeback abuse') !== -1 &&
    blockedHtml.indexOf('data-action="unblock-arm"') !== -1 && blockedHtml.indexOf('devices stay revoked') !== -1);
  const blockedRows = Core.renderBanksRowsHtml([{ biomId: 'B', name: 'n', hand: 'left', edccCount: 1, neuralCount: 1, version: 1, deleted: false, blocked: true }]);
  check('V78 BLOCK the banks table flags a blocked person with a badge',
    blockedRows.indexOf('badge badge-denied">Blocked<') !== -1);
  const logHtml = Core.renderAdminLogHtml([
    { id: 'a1', ts: 1764200000000, action: 'block', biomId: 'TSG-BIO-2841', reason: 'Chargeback abuse', revokedDeviceIds: ['dev-1'] },
    { id: 'a2', ts: 1764300000000, action: 'unblock', biomId: 'TSG-BIO-2841', reason: '', revokedDeviceIds: [] }
  ]);
  check('V78 the admin log renders actions, reasons and revoked-device counts; empty log reads intentionally',
    logHtml.indexOf('Chargeback abuse') !== -1 && logHtml.indexOf('>Block</span>') !== -1 && logHtml.indexOf('>Unblock</span>') !== -1 &&
    Core.renderAdminLogHtml([]).indexOf('No block or unblock has been recorded yet.') !== -1);
  const adminCalls = [];
  const adminFetch = function (url, opts) {
    adminCalls.push({ url: url, opts: opts });
    if (url.indexOf('/api/admin/log') !== -1) return Promise.resolve({ status: 200, ok: true, json: function () { return Promise.resolve({ ok: true, count: 0, entries: [] }); } });
    return Promise.resolve({ status: 200, ok: true, json: function () { return Promise.resolve({ ok: true, biomId: 'TSG-BIO-2841', blocked: true, revokedDeviceIds: ['dev-1'] }); } });
  };
  const blockRes = await Core.adminBlock('https://api.test/', 'admin-key-1', 'TSG-BIO-2841', 'Chargeback abuse', adminFetch);
  check('V78 ADMIN block posts to /api/admin/block with the admin key in the header only',
    blockRes.blocked === true && adminCalls[0].url === 'https://api.test/api/admin/block' &&
    adminCalls[0].opts.headers['x-admin-key'] === 'admin-key-1' && adminCalls[0].url.indexOf('admin-key-1') === -1 &&
    JSON.parse(adminCalls[0].opts.body).reason === 'Chargeback abuse');
  const logEntries = await Core.adminLog('https://api.test', 'admin-key-1', adminFetch);
  check('V78 ADMIN the log reads via GET with the admin key and returns the entries array',
    Array.isArray(logEntries) && adminCalls[1].opts.method === 'GET');
  let notConfigured = null;
  try {
    await Core.adminBlock('https://api.test', 'admin-key-1', 'B', '', function () {
      return Promise.resolve({ status: 503, ok: false, json: function () { return Promise.resolve({ error: 'admin not configured', adminConfigured: false }); } });
    });
  } catch (e) { notConfigured = e; }
  check('V78 ADMIN a 503 keeps its body on the error so the UI can say "not configured" (never fail open)',
    !!notConfigured && notConfigured.status === 503 && notConfigured.body.adminConfigured === false);

  /* ---- v79: auto-block surfacing — actor, system entries, IPs, tamper flag ---- */
  const log79 = Core.renderAdminLogHtml([
    { id: 'b1', ts: 1764200000000, action: 'block', biomId: 'TSG-BIO-2841', actor: 'chairman', reason: 'Manual review', revokedDeviceIds: ['dev-1'], blockedIps: ['203.0.113.7'] },
    { id: 'b2', ts: 1764300000000, action: 'block', biomId: 'TSG-BIO-3000', actor: 'system', reason: 'Auto-block (velocity escalation): 2 velocity holds within 1 day', revokedDeviceIds: ['dev-9'] },
    { id: 'b3', ts: 1764400000000, action: 'revoke-device', biomId: '', actor: 'system', reason: 'Auto-revoked (technical tampering): 10 signature or sequence violations', revokedDeviceIds: ['dev-x'] },
    { id: 'b4', ts: 1764500000000, action: 'unblock', biomId: 'TSG-BIO-2841', actor: 'chairman', reason: '', revokedDeviceIds: [], liftedIps: ['203.0.113.7'] },
    { id: 'b5', ts: 1764600000000, action: 'block', biomId: 'TSG-BIO-OLD', reason: 'Pre-v79 manual block', revokedDeviceIds: [] }
  ]);
  check('V79 LOG the admin log has an actor column distinguishing the Chairman from the system',
    log79.indexOf('<th scope="col">By</th>') !== -1 && log79.indexOf('System (auto)') !== -1 && log79.indexOf('Chairman') !== -1);
  check('V79 LOG a system block reads Auto-block; a device revocation reads Device revoked; legacy entries read as the Chairman',
    log79.indexOf('>Auto-block</span>') !== -1 && log79.indexOf('>Device revoked</span>') !== -1 &&
    log79.indexOf('Pre-v79 manual block') !== -1);
  check('V79 LOG IP effects ride the reason cell (blocked on block, lifted on unblock)',
    log79.indexOf('IPs blocked: 203.0.113.7') !== -1 && log79.indexOf('IPs lifted: 203.0.113.7') !== -1);
  const ipsHtml = Core.renderBlockedIpsHtml([
    { ip: '203.0.113.7', biomId: 'TSG-BIO-2841', ts: 1764200000000, actor: 'chairman' },
    { ip: '198.51.100.9', biomId: 'TSG-BIO-3000', ts: 1764300000000, actor: 'system' }
  ]);
  check('V79 IPS the blocked-IP table renders IP, linked person, time and actor',
    ipsHtml.indexOf('203.0.113.7') !== -1 && ipsHtml.indexOf('TSG-BIO-3000') !== -1 && ipsHtml.indexOf('System (auto)') !== -1);
  check('V79 IPS an empty registry explains itself (and the rule) instead of a blank',
    Core.renderBlockedIpsHtml([]).indexOf('No IP addresses are blocked right now') !== -1);
  const ipsCalls = [];
  const ipsFetch = function (url, opts) {
    ipsCalls.push({ url: url, opts: opts });
    return Promise.resolve({ status: 200, ok: true, json: function () { return Promise.resolve({ ok: true, count: 1, entries: [{ ip: '203.0.113.7', biomId: 'B', ts: 1, actor: 'system' }], ips: ['203.0.113.7'] }); } });
  };
  const ipsEntries = await Core.adminBlockedIps('https://api.test/', 'admin-key-1', ipsFetch);
  check('V79 IPS the registry reads via GET /api/admin/blocked-ips with the admin key in the header only',
    ipsEntries.length === 1 && ipsCalls[0].url === 'https://api.test/api/admin/blocked-ips' &&
    ipsCalls[0].opts.method === 'GET' && ipsCalls[0].opts.headers['x-admin-key'] === 'admin-key-1' && ipsCalls[0].url.indexOf('admin-key-1') === -1);
  const autoBlockedHtml = Core.renderBlockActionHtml(
    { biomId: 'B2', deleted: false, blocked: true, blockedBy: 'system', blockedTs: 1764200000000, blockedReason: 'Auto-block (spoofing): 5 spoof presentation verdicts', blockedIps: ['203.0.113.7', '198.51.100.9'] },
    { adminKeyPresent: true });
  check('V79 DOSSIER an auto-blocked person shows Blocked by System, the reason, and their blocked IPs',
    autoBlockedHtml.indexOf('System (auto-block)') !== -1 && autoBlockedHtml.indexOf('Auto-block (spoofing)') !== -1 &&
    autoBlockedHtml.indexOf('203.0.113.7') !== -1 && autoBlockedHtml.indexOf('lifts the IP block') !== -1);
  const manualBlockedHtml = Core.renderBlockActionHtml(
    { biomId: 'B3', deleted: false, blocked: true, blockedTs: 1764200000000, blockedReason: 'Fraud' },
    { adminKeyPresent: true });
  check('V79 DOSSIER a pre-v79 / manual block reads Blocked by Chairman (absent blockedBy is never shown as system)',
    manualBlockedHtml.indexOf('<dt>Blocked by</dt><dd>Chairman</dd>') !== -1 && manualBlockedHtml.indexOf('System (auto-block)') === -1);
  const tamperHtml = Core.renderBlockActionHtml(
    { biomId: 'B4', deleted: false, blocked: false, tamperFlags: { rollbackAttempts: 2, lastRollbackTs: 1764200000000 } },
    { adminKeyPresent: true });
  check('V79 DOSSIER a rollback tamper flag is surfaced with its count and the stale-device caveat',
    tamperHtml.indexOf('Ledger rollback attempts refused: 2') !== -1 && tamperHtml.indexOf('stale second device') !== -1);
  const cleanHtml = Core.renderBlockActionHtml(FULL[0], { adminKeyPresent: true });
  check('V79 DOSSIER a person with no flag shows no tamper warning',
    cleanHtml.indexOf('Ledger rollback attempts refused') === -1);
  const hostileLog = Core.renderAdminLogHtml([
    { id: 'h1', ts: 1, action: 'block', biomId: 'B', actor: 'system', reason: '<script>alert(7)</script>', revokedDeviceIds: [], blockedIps: ['<b>1.2.3.4</b>'] }
  ]);
  check('V79 ESCAPING hostile reason / IP text in the log renders as text',
    hostileLog.indexOf('<script>alert(7)</script>') === -1 && hostileLog.indexOf('&lt;script&gt;') !== -1 && hostileLog.indexOf('<b>1.2.3.4</b>') === -1);

  /* ---- v80: impersonation + duplicate-enrolment flags, cross-match scan rows ---- */
  const v80Scans = [
    { id: 'x1', ts: 1764200000000, kind: 'money-auth', biomId: 'BIO-ATK', result: 'Denied', crossNeuralId: 'B5', crossNeuralScore: 0.55 },
    { id: 'x2', ts: 1764300000000, kind: 'identify', biomId: '', result: 'Denied', crossEdccId: 'B5', crossEdccScore: 0.29, crossNeuralId: 'B5', crossNeuralScore: 0.61 },
    { id: 'x3', ts: 1764400000000, kind: 'money-auth', biomId: 'BIO-ATK', result: 'Denied', fieldTest: true, crossNeuralId: 'B5', crossNeuralScore: 0.9 },
    { id: 'x4', ts: 1764500000000, kind: 'enrol', biomId: 'B5', result: 'Enrolment Refused — Duplicate Palm', edccScore: 0.4 },
    { id: 'x5', ts: 1764600000000, kind: 'enrol', biomId: 'B5', result: 'Enrolled' },
    { id: 'x6', ts: 1764700000000, kind: 'money-auth', biomId: 'BIO-ATK', result: 'Denied', crossNeuralId: 'SOMEONE-ELSE', crossNeuralScore: 0.7 }
  ];
  const flaggedHtml = Core.renderBlockActionHtml({ biomId: 'B5', deleted: false, blocked: false }, { adminKeyPresent: true }, v80Scans);
  check('V80 DOSSIER the impersonation flag counts only denied records naming this person (field-test excluded), with per-system strongest scores',
    flaggedHtml.indexOf('Impersonation attempts targeting this person: 2 recorded') !== -1 &&
    flaggedHtml.indexOf('strongest: EDCC 0.290 · PalmNet 0.610') !== -1 &&
    flaggedHtml.indexOf('never blocked for being targeted') !== -1);
  check('V80 DOSSIER the duplicate-enrolment flag counts refusal records only (a successful enrolment is not one)',
    flaggedHtml.indexOf('Duplicate enrolment refused: 1 attempt to enrol this palm again') !== -1 &&
    flaggedHtml.indexOf('nothing was created') !== -1);
  const unflaggedHtml = Core.renderBlockActionHtml({ biomId: 'B6', deleted: false, blocked: false }, { adminKeyPresent: true }, v80Scans);
  check('V80 DOSSIER a person named by no record shows neither flag',
    unflaggedHtml.indexOf('Impersonation attempts targeting') === -1 && unflaggedHtml.indexOf('Duplicate enrolment refused') === -1);
  const noScansHtml = Core.renderBlockActionHtml({ biomId: 'B5', deleted: false, blocked: false }, { adminKeyPresent: true });
  check('V80 DOSSIER the flags render nothing when no scans are supplied (older callers unaffected)',
    noScansHtml.indexOf('Impersonation attempts targeting') === -1 && noScansHtml.indexOf('Duplicate enrolment refused') === -1);
  const cardHtml = Core.renderScanCardsHtml([
    { id: 'c1', ts: 1764200000000, kind: 'money-auth', profileName: 'Fixture', biomId: '', result: 'Denied', edccScore: 0.1, palmnetScore: 0.2, crossEdccId: 'B5', crossEdccScore: 0.29, crossNeuralId: 'B5', crossNeuralScore: 0.61 }
  ]);
  check('V80 SCANS a card with cross-match evidence shows the closest other palm with both scores',
    cardHtml.indexOf('Closest other palm') !== -1 && cardHtml.indexOf('B5 · EDCC 0.290 · PalmNet 0.610') !== -1);
  const plainCardHtml = Core.renderScanCardsHtml([
    { id: 'c2', ts: 1764200000000, kind: 'money-auth', profileName: 'Fixture', biomId: 'B5', result: 'Denied', edccScore: 0.1, palmnetScore: 0.2 }
  ]);
  check('V80 SCANS a pre-v80 record renders no cross-match row (byte-stable card)',
    plainCardHtml.indexOf('Closest other palm') === -1);
  const hostileCard = Core.renderScanCardsHtml([
    { id: 'c3', ts: 1764200000000, kind: 'money-auth', profileName: 'Fixture', biomId: '', result: 'Denied', crossNeuralId: '<script>alert(9)</script>', crossNeuralScore: 0.5 }
  ]);
  check('V80 ESCAPING a hostile cross-match id renders as text, never markup',
    hostileCard.indexOf('<script>alert(9)</script>') === -1 && hostileCard.indexOf('&lt;script&gt;') !== -1);

  /* ---------- v81: research-frame count (simulation mode) ------ */
  const statsR = Core.computeStats(data.scans, data.profiles, { bundles: 4, frames: 11, byDay: { '2026-11-27': 11 } });
  check('V81 STATS computeStats carries the research count through', statsR.research && statsR.research.frames === 11 && statsR.research.bundles === 4);
  const statsRHtml = Core.renderStatsHtml(statsR);
  check('V81 STATS the stats strip gains a Research frames card when the API reported a count',
    statsRHtml.indexOf('Research frames') !== -1 && statsRHtml.indexOf('>11<') !== -1 && statsRHtml.indexOf('4 bundles received') !== -1);
  check('V81 STATS without a research count the strip is unchanged (no card)',
    Core.renderStatsHtml(stats).indexOf('Research frames') === -1);
  const rcOk = await Core.loadResearchCount('https://api.test', 'ak', function (url, opts) {
    check('V81 COUNT the count is read from /api/admin/research with the ADMIN key (the route is admin-gated)',
      url === 'https://api.test/api/admin/research' && opts.headers['x-admin-key'] === 'ak');
    return Promise.resolve({ ok: true, status: 200, json: function () { return Promise.resolve({ bundles: 4, frames: 11, byDay: {} }); } });
  });
  check('V81 COUNT a well-formed count resolves through', !!rcOk && rcOk.frames === 11 && rcOk.bundles === 4);
  const rcBad = await Core.loadResearchCount('https://api.test', 'ak', function () {
    return Promise.resolve({ ok: false, status: 404, json: function () { return Promise.resolve({}); } });
  });
  check('V81 COUNT an older API without the route resolves null — the dashboard load is never broken by it', rcBad === null);
  const rcNone = await Core.loadResearchCount('https://api.test', '', function () { throw new Error('must not be called'); });
  check('V81 COUNT without an admin key the count is skipped (null), never attempted', rcNone === null);

  /* ---------- v82 (Phase 6): research-delete control, person
     field audit, seal cross-compatibility -------------------- */
  const rdCalls = [];
  const rdFetch = function (url, opts) {
    rdCalls.push({ url: url, opts: opts });
    return Promise.resolve({ status: 200, ok: true, json: function () { return Promise.resolve({ ok: true, researchId: 'res-fixture-1', removed: 3 }); } });
  };
  const rdRes = await Core.adminResearchDelete('https://api.test/', 'admin-key-1', 'res-fixture-1', rdFetch);
  check('V82 RESEARCH-DELETE posts to /api/admin/research-delete with {researchId} and the admin key in the header only',
    rdRes.removed === 3 && rdCalls[0].url === 'https://api.test/api/admin/research-delete' &&
    rdCalls[0].opts.method === 'POST' && rdCalls[0].opts.headers['x-admin-key'] === 'admin-key-1' &&
    rdCalls[0].url.indexOf('admin-key-1') === -1 && JSON.parse(rdCalls[0].opts.body).researchId === 'res-fixture-1');
  let rd400 = null;
  try {
    await Core.adminResearchDelete('https://api.test', 'ak', '', function () {
      return Promise.resolve({ status: 400, ok: false, json: function () { return Promise.resolve({ error: 'researchId required' }); } });
    });
  } catch (e) { rd400 = e; }
  check('V82 RESEARCH-DELETE a 400 keeps its body on the error so the UI can state the refusal plainly',
    !!rd400 && rd400.status === 400 && rd400.body.error === 'researchId required');
  const rdNoKey = Core.renderResearchDeleteHtml({ adminKeyPresent: false });
  check('V82 RESEARCH-DELETE with no admin key sealed, the control explains itself and renders NO actionable button',
    rdNoKey.indexOf('not set up on this browser') !== -1 && rdNoKey.indexOf('data-action="research-delete-arm"') === -1 &&
    rdNoKey.indexOf('data-action="research-delete-confirm"') === -1 && rdNoKey.indexOf('researchCodeInput') === -1);
  const rdUnarmed = Core.renderResearchDeleteHtml({ adminKeyPresent: true });
  check('V82 RESEARCH-DELETE the unarmed state is an input + arm button only (no confirm exists yet)',
    rdUnarmed.indexOf('id="researchCodeInput"') !== -1 && rdUnarmed.indexOf('data-action="research-delete-arm"') !== -1 &&
    rdUnarmed.indexOf('data-action="research-delete-confirm"') === -1);
  const rdArmed = Core.renderResearchDeleteHtml({ adminKeyPresent: true, armed: true, code: 'res-fixture-1' });
  check('V82 RESEARCH-DELETE the armed state echoes the exact code, warns it is permanent, and offers confirm + cancel (two-step rule)',
    rdArmed.indexOf('res-fixture-1') !== -1 && rdArmed.indexOf('permanently deletes') !== -1 &&
    rdArmed.indexOf('data-action="research-delete-confirm"') !== -1 && rdArmed.indexOf('data-action="research-delete-cancel"') !== -1 &&
    rdArmed.indexOf('researchCodeInput') === -1);
  const rdBusy = Core.renderResearchDeleteHtml({ adminKeyPresent: true, armed: true, code: 'res-fixture-1', busy: true });
  check('V82 RESEARCH-DELETE while busy, confirm and cancel are disabled (no double-fire)',
    (rdBusy.match(/disabled/g) || []).length >= 2);
  const rdHostile = Core.renderResearchDeleteHtml({ adminKeyPresent: true, armed: true, code: '<script>alert(5)</script>' });
  check('V82 ESCAPING a hostile research code in the confirm echo renders as text',
    rdHostile.indexOf('<script>alert(5)</script>') === -1 && rdHostile.indexOf('&lt;script&gt;') !== -1);
  check('V82 RESEARCH-DELETE the control lives in Settings → Admin activity and the wiring pins the armed code',
    pageHtml.indexOf('id="researchDeleteBody"') !== -1 && pageHtml.indexOf('id="researchDeleteBody"') > pageHtml.indexOf('id="adminActivityCard"') &&
    dashAppSrc.indexOf("'research-delete-confirm'") !== -1 && dashAppSrc.indexOf("'research-delete-arm'") !== -1 &&
    dashAppSrc.indexOf('researchUi.armedCode') !== -1 && dashAppSrc.indexOf('Core.adminResearchDelete(') !== -1);

  /* Field audit (Phase 6 addition): image honesty + wallet rows */
  check('V82 FIELDS the person view states the image position honestly (anonymous research frames, never linked)',
    control.indexOf('No consented image is linked to this person') !== -1 && control.indexOf('anonymous by design') !== -1 &&
    control.indexOf('<img') === -1);
  check('V82 FIELDS the rail derives from real mirror data (the Add entry account type) when no walletLink is served',
    control.indexOf('<dt>Rail</dt><dd>bKash</dd>') !== -1);
  const linkedControl = Core.renderPersonControlHtml({ biomId: 'L1', name: 'Linked', deleted: false, walletLink: { provider: 'bkash', maskedWallet: '017•• •••8575', linkedTs: 1764000000000 }, wallet: { balance: 10, statement: [] } }, []);
  check('V82 FIELDS a served walletLink renders its masked wallet number and rail (future-proof for the API gap fix)',
    linkedControl.indexOf('017•• •••8575') !== -1 && linkedControl.indexOf('<dt>Rail</dt><dd>bKash</dd>') !== -1);
  check('V82 FIELDS without a served walletLink the rows say so plainly — the full number is never invented',
    legacyControl.indexOf('Not served by the API summary yet') !== -1 && legacyControl.indexOf('<dt>Rail</dt><dd>Not captured</dd>') !== -1 &&
    legacyControl.indexOf('never stored on the server') !== -1);

  /* Seal cross-compatibility, INDEPENDENT implementation: an
     envelope built with Node's crypto directly from the v1 spec
     (PBKDF2-SHA-256 600k, AES-256-GCM, tag appended — the exact
     format the live pre-v82 code writes) must open with the final
     Core, and a Core seal must open with the independent code.
     This is the Chairman's unlock surviving the declutter. */
  const nodeCrypto = require('crypto');
  const fxSalt = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
  const fxIv = Buffer.from('0102030405060708090a0b0c', 'hex');
  const fxKey = nodeCrypto.pbkdf2Sync('fixture-password-82', fxSalt, 600000, 32, 'sha256');
  const fxCipher = nodeCrypto.createCipheriv('aes-256-gcm', fxKey, fxIv);
  const fxPayload = JSON.stringify({ endpoint: 'https://api.test', readKey: 'rk-fixture', adminKey: 'ak-fixture' });
  const fxCt = Buffer.concat([fxCipher.update(fxPayload, 'utf8'), fxCipher.final(), fxCipher.getAuthTag()]);
  const fxSealed = { v: 1, iter: 600000, salt: fxSalt.toString('base64'), iv: fxIv.toString('base64'), ct: fxCt.toString('base64') };
  const fxOpened = await Core.unsealCredentials('fixture-password-82', fxSealed);
  check('V82 SEAL-COMPAT an envelope sealed by the CURRENT (pre-v82) algorithm opens with the final code, byte-exact',
    fxOpened.endpoint === 'https://api.test' && fxOpened.readKey === 'rk-fixture' && fxOpened.adminKey === 'ak-fixture');
  const coreSealed = await Core.sealCredentials('fixture-password-82', { endpoint: 'https://api.test', readKey: 'rk-fixture', adminKey: 'ak-fixture' });
  const cKey = nodeCrypto.pbkdf2Sync('fixture-password-82', Buffer.from(coreSealed.salt, 'base64'), coreSealed.iter, 32, 'sha256');
  const cRaw = Buffer.from(coreSealed.ct, 'base64');
  const cDec = nodeCrypto.createDecipheriv('aes-256-gcm', cKey, Buffer.from(coreSealed.iv, 'base64'));
  cDec.setAuthTag(cRaw.slice(cRaw.length - 16));
  const cPt = Buffer.concat([cDec.update(cRaw.slice(0, cRaw.length - 16)), cDec.final()]).toString('utf8');
  const cObj = JSON.parse(cPt);
  check('V82 SEAL-COMPAT a seal written by the final code opens with the independent pre-v82 algorithm (reverse direction)',
    cObj.readKey === 'rk-fixture' && cObj.adminKey === 'ak-fixture' && coreSealed.v === 1 && coreSealed.iter === 600000);
  check('V82 the seal code itself is untouched by the declutter (same storage key, same envelope fields)',
    dashAppSrc.indexOf("var LS_SEALED = 'tsgBiomControl.sealed';") !== -1 &&
    dashAppSrc.indexOf('v: 1, iter: PBKDF2_ITERATIONS') !== -1);

  console.log('\n' + (fail === 0 ? 'ALL DASHBOARD TESTS PASSED (' + pass + ')' : fail + ' FAILURES, ' + pass + ' passed'));
  process.exit(fail === 0 ? 0 : 1);
}

main().catch(function (e) { console.error(e); process.exit(1); });
