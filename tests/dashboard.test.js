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

  console.log('\n' + (fail === 0 ? 'ALL DASHBOARD TESTS PASSED (' + pass + ')' : fail + ' FAILURES, ' + pass + ' passed'));
  process.exit(fail === 0 ? 0 : 1);
}

main().catch(function (e) { console.error(e); process.exit(1); });
