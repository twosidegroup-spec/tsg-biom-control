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

## The read key

On first open, the dashboard asks for the API endpoint and the **read key** — the
`READ_KEY` value set in the API server's environment (the same key the API checks on
every read; it is *not* the device key the phone uses to write).

- The owner types the key into the page in their own browser.
- It is stored only in that browser's `localStorage`, alongside the endpoint, and is
  sent only to the API as the `x-read-key` header.
- **Disconnect** (top right) clears both values from the browser.
- One honest note on storage: this dashboard and the BIOM app are served from the
  SAME origin (`twosidegroup-spec.github.io`), and browsers scope `localStorage`
  per origin, not per page — so the two apps' stored values coexist in one
  origin-wide store. The dashboard's keys are namespaced (`tsgBiomControl.*`) and
  the app's are too, so neither reads the other's values; but a browser-level
  "clear site data" for the origin would clear BOTH, including the app's
  enrolments. Never clear site data for this origin — the app's own Delete All
  Data is the only erase, and it is deliberate.
- If the API refuses the key (HTTP 401), the dashboard says the key was refused and
  offers to re-enter it — it never retries silently with a different key.

Anyone who opens the page without the key sees only the connect form.

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
