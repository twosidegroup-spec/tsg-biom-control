# TSG Biom Control

The control dashboard for the TSG BIOM palm biometric system (TwoSide Group).
It shows, in one place, everything your devices sync to your own TSG Biom API:

- **Overview** — total scans, verified count, denied count, enrolled profiles, last scan time (Asia/Dhaka).
- **Scan records** — time, kind (enrolment, verify, wallet open, money auth, and the rest), profile,
  hand, EDCC score, PalmNet score, result badge and device label, with filters by kind and result
  plus a name / Biom ID search. Newest first.
- **Enrolled palms** — one card per profile: name, Biom ID, hand, EDCC template count,
  PalmNet embedding count, model stamp, bank version, encryption state, owner device
  and last updated. A bank deleted on a device (a tombstone) shows as a **Removed**
  card with its deletion time, and the Overview count covers live banks only.
  Template and embedding *contents* are never displayed — counts only.

**v82 (Phase 6):** Settings → Admin activity gains the research-frame withdrawal
control — enter an anonymous research code, confirm, and every stored research
bundle for that code is deleted via `POST /api/admin/research-delete` (the v81
privacy promise, now operable from the dashboard). The person dossier also states
the image position honestly (research frames are anonymous by design and are
never linked to a person) and shows linked-wallet / rail rows from the data the
server actually serves. The credential seal format is unchanged from v63–v81.

The page is a plain static site (`index.html`, `styles.css`, `app.js`). There is no build
step and there are no external dependencies — no CDNs, no frameworks, nothing to install.
It is fully responsive: phone first, then tablet and desktop.

## Where the data comes from

The dashboard reads two endpoints from the TSG Biom API
(default `https://tsg-biom-api.vercel.app`):

- `GET /api/scans` — the synced scan records
- `GET /api/profiles?summary=1` — the synced palm banks as SUMMARIES (v62)

Both are called with the read key in the `x-read-key` header. The page contains no data
of its own and never shows sample records: if the API returns nothing, the page says so.
Since v62 the dashboard uses the summary endpoint on purpose: it receives counts,
versions, encryption state, owner device and tombstone flags — never the template
strings themselves — so opening the dashboard no longer downloads every full bank
just to show counts.

## The read key and the dashboard password (v63)

Login is **password-only**. On first open, the dashboard asks once for the API
endpoint and the **read key** — the `READ_KEY` value set in the API server's
environment (the same key the API checks on every read; it is *not* the device
key the phone uses to write) — and for the **dashboard password** the owner
chooses. From then on, every visit asks only for the password.

- The owner types the key into the page in their own browser, once.
- The endpoint + key are stored in that browser's `localStorage` **sealed** —
  AES-GCM-256 under a key derived from the dashboard password with
  PBKDF2-SHA-256 (600,000 iterations, random salt, fresh IV per seal). They are
  never stored in plain text (this closes the pre-v63 note that used to stand
  here). The password itself is stored nowhere: a correct password is simply
  one whose derived key opens the seal.
- Until the password unlocks the seal, the page makes **no API call at all**;
  a wrong password stays on the lock screen with an honest message. **Lock**
  (top right) re-locks without forgetting; **Disconnect** clears the sealed
  record from the browser entirely.
- A browser that still holds the pre-v63 plaintext key is migrated on its next
  visit: set the password once, the key is sealed, and the plaintext entries
  are deleted.
- One honest note on storage: this dashboard and the BIOM app are served from
  the SAME origin (`twosidegroup-spec.github.io`), and browsers scope
  `localStorage` per origin, not per page — so the two apps' stored values
  coexist in one origin-wide store. The dashboard's keys are namespaced
  (`tsgBiomControl.*`) and the app's are too, so neither reads the other's
  values; but a browser-level "clear site data" for the origin would clear
  BOTH, including the app's enrolments. Never clear site data for this
  origin — the app's own Delete All Data is the only erase, and it is
  deliberate.
- If the API refuses the key (HTTP 401), the dashboard says the key was refused
  and offers to re-enter it — it never retries silently with a different key.

Anyone who opens the page without the password sees only the lock screen.

## Security posture and the GitHub Pages limits (v64)

- **Content Security Policy.** The dashboard ships a strict CSP
  in a `<meta>` tag: `default-src 'none'`, scripts from `'self'`
  only, and `connect-src` pinned to the one TSG Biom API this
  build talks to. It also sends `referrer: no-referrer` by meta.
- **What meta cannot do — stated plainly.** GitHub Pages cannot
  send custom response headers, so: `frame-ancestors` (clickjacking
  framing protection) and CSP reporting cannot be expressed in a
  meta tag and are **absent** on this host; HSTS and
  Permissions-Policy cannot be set by meta at all. The residual
  framing exposure is a read-only owner console behind a
  password-sealed key; it closes the day the dashboard moves to
  a host that can send headers. The API itself sends the full
  header set from code (see the API README).
- **Escaping.** Every API-supplied field is rendered through the
  dashboard's `esc()` — proven by a hostile-fixture test: a
  profile name or scan field containing markup renders as text,
  never as markup.
- **Password floor.** Setup and migration refuse dashboard
  passwords under 8 characters (the password is the only thing
  protecting the sealed read key). Unlock is never length-checked:
  an existing seal always opens with the password it was made with.

## Going live (GitHub Pages)

The dashboard is designed to sit on the same GitHub Pages origin as the BIOM app
(`twosidegroup-spec.github.io`), which is the origin the API's CORS allowlist trusts.

1. Create a **public** repository named `tsg-biom-control` under `twosidegroup-spec`
   (GitHub Pages for user sites serves project repos from the same origin).
2. Push these four files to the repo's `main` branch: `index.html`, `styles.css`,
   `app.js`, `README.md`.
3. In the repo, open **Settings → Pages**, set Source to **Deploy from a branch**,
   branch `main`, folder `/ (root)`, and save.
4. The dashboard goes live at `https://twosidegroup-spec.github.io/tsg-biom-control/`.
5. Open it, enter the endpoint and your read key, and connect.

## Local check

```sh
npm test   # headless proof of the data path (summary fetch, rendering, stats)
```

Serve the folder with any static server, for example:

Serve the folder with any static server, for example:

```sh
python3 -m http.server 8080 --directory .
```

then open `http://localhost:8080/`. Note the live API only accepts browser calls from
the `twosidegroup-spec.github.io` origin (its CORS allowlist), so a locally served page
can render and be inspected, but live reads succeed from the Pages deployment.
