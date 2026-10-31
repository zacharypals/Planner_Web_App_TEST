# LP Planner v4.1.0 (D1 test build) — setup

This build stores planner data in Cloudflare D1 through a new Worker, `planner-api`, instead of the Google Drive file. It runs only in **Planner_Web_App_TEST**. The live app, `planner-auth`, and your Drive file are not touched.

The test app starts with **empty data**. From v4.1.0, the **☁ Data** panel imports your Drive data and shows the nightly backups.

All commands are PowerShell. Paths used:

| | |
|---|---|
| Downloads | `C:\Users\slapc\OneDrive\Documents\Downloads` |
| Local repo | `C:\Users\slapc\OneDrive\Documents\Personal\ProjectsVS\Planner_Tracker_D1` |
| GitHub repo | https://github.com/zacharypals/Planner_Web_App_TEST |

---

## Updating to v4.1.0 (Drive import + nightly backups)

Already set up with v4.0.0? These are the only steps. Run them in PowerShell.

```powershell
# 1) Unzip over the repo (this zip does not contain worker\wrangler.toml, so your database ID is safe)
Expand-Archive -Path "C:\Users\slapc\OneDrive\Documents\Downloads\LP_Planner_v4.1.0_D1_test.zip" -DestinationPath "C:\Users\slapc\OneDrive\Documents\Personal\ProjectsVS\Planner_Tracker_D1" -Force

cd "C:\Users\slapc\OneDrive\Documents\Personal\ProjectsVS\Planner_Tracker_D1\worker"

# 2) Add the nightly schedule to wrangler.toml (ONE TIME ONLY — running it twice adds a duplicate block)
Add-Content -Path wrangler.toml -Value "`n[triggers]`ncrons = [`"0 10 * * *`"]"
Get-Content wrangler.toml -Tail 3        # should end with:  crons = ["0 10 * * *"]

# 3) Add the backup-status columns to the database
npx wrangler d1 migrations apply planner-db --remote

# 4) Deploy the Worker. The output should list:  schedule: 0 10 * * *
npx wrangler deploy

# 5) Publish the app
cd ..
git add -A
git commit -m "v4.1.0: Drive import/restore + nightly Drive backups (Worker 0.2.0)"
git push
```

`0 10 * * *` is 10:00 UTC: 3 AM Pacific in summer, 2 AM in winter.

Then, in the app (refresh until the nav bar shows **v4.1.0**), tap **☁ Data**:

1. **Back up now**: the line above the button should turn green with today's file name, and a folder called **LP Planner Backups** appears in your Google Drive with that file in it.
2. **Find files in Google Drive** → **Live app data (planner-data.json)**. Check the counts (weeks, tasks, pages, and so on), then tap **Replace my data with this file**. This replaces your test entries with your real data and should finish with "✓ Import complete and verified". The Drive file itself isn't changed.
3. The next morning, check that **☁ Data** shows a new backup from around 3 AM. That confirms the nightly job runs on its own.

If the panel says Google Drive access isn't granted, tap **Reconnect Google** and approve Drive.

**Cloudflare's own safety net:** D1 keeps 7 days of history automatically on the free plan (Time Travel). Nothing to turn on. To roll the whole database back, for example to 8 AM Pacific on Nov 1:
```powershell
npx wrangler d1 time-travel restore planner-db --timestamp="2026-11-01T08:00:00-07:00"
```
That rewinds everyone's data, so treat it as a last resort. For one person's data, restoring a Drive backup through **☁ Data** is the normal route.

---

## 1. Clone the test repo into the empty folder (one time)

The local folder must be a clone of the GitHub repo, so that `git push` publishes it. The trailing `.` clones into the current folder, which must be empty.

```powershell
cd "C:\Users\slapc\OneDrive\Documents\Personal\ProjectsVS\Planner_Tracker_D1"
git clone https://github.com/zacharypals/Planner_Web_App_TEST.git .
# OneDrive locks files inside .git, so turn off Git's auto-cleanup (same fix as Finance Pal):
git config gc.auto 0
```

You now have the repo's current files, including the old `PlannerWorker` folder. That's the live app's Worker; it isn't used here, so leave it alone.

## 2. Unzip this update over it

```powershell
Expand-Archive -Path "C:\Users\slapc\OneDrive\Documents\Downloads\LP_Planner_v4.0.0_D1_test.zip" -DestinationPath "C:\Users\slapc\OneDrive\Documents\Personal\ProjectsVS\Planner_Tracker_D1" -Force
```

If the browser saved the download as `LP_Planner_v4.0.0_D1_test (1).zip`, use that name instead.

Check it worked. This should print `<!-- LP Planner v4.0.0 -->`:

```powershell
Get-Content "C:\Users\slapc\OneDrive\Documents\Personal\ProjectsVS\Planner_Tracker_D1\index.html" -TotalCount 2
```

## 3. Google Cloud: allow the test app's sign-in page (in the browser)

1. Open https://console.cloud.google.com/apis/credentials (same project as LP Planner).
2. Open the OAuth client whose ID ends in `…mbtlguuf` (the one LP Planner uses).
3. Under **Authorized redirect URIs**, click **Add URI** and enter:
   `https://zacharypals.github.io/Planner_Web_App_TEST/oauth.html`
4. Click **Save**.
5. On the same page, copy the **Client secret**. Step 4 asks for it.

The test app reuses this client on purpose: Phase 4 has to read `planner-data.json`, which only this client can open.

## 4. Cloudflare: create the database and deploy the Worker

Run these from the `worker` subfolder:

```powershell
cd "C:\Users\slapc\OneDrive\Documents\Personal\ProjectsVS\Planner_Tracker_D1\worker"

# Log in (same Cloudflare account as Finance Pal). Skip this if `npx wrangler whoami` shows you're logged in.
npx wrangler login

# Create the database. It prints a block that includes:  database_id = "xxxxxxxx-xxxx-..."
npx wrangler d1 create planner-db
```

Put that ID into `wrangler.toml`. Replace `PASTE-THE-ID-HERE` with the ID, keeping the quotes:

```powershell
(Get-Content wrangler.toml) -replace 'PASTE_ID_FROM_wrangler_d1_create', 'PASTE-THE-ID-HERE' | Set-Content wrangler.toml
Select-String -Path wrangler.toml -Pattern 'database_id'    # should show your ID
```

Create the tables:

```powershell
npx wrangler d1 migrations apply planner-db --remote
```

Set the two secrets:

```powershell
# 1) Google client secret. Paste the value from step 3 when asked.
npx wrangler secret put GOOGLE_CLIENT_SECRET

# 2) Encryption key for stored Google tokens. Generated and sent straight to Cloudflare, so there's nothing to copy.
$b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
[Convert]::ToBase64String($b) | npx wrangler secret put TOKEN_ENC_KEY
```

Deploy:

```powershell
npx wrangler deploy
```

`wrangler deploy` prints the Worker's URL. If it isn't `https://planner-api.plannertracker.workers.dev`, tell me the printed URL; `APP_CONFIG.API_URL` in `index.html` needs to match it.

Check it's running. This should print `ok: True` and `version: 0.1.0`:

```powershell
Invoke-RestMethod https://planner-api.plannertracker.workers.dev/health
```

If you see Cloudflare errors 7403 or 10007 on first use, run `npx wrangler logout`, then `npx wrangler login`, then repeat the step that failed. That fixed the same errors for Finance Pal.

## 5. Publish the test site

Run these from the repo root:

```powershell
cd "C:\Users\slapc\OneDrive\Documents\Personal\ProjectsVS\Planner_Tracker_D1"
git add -A
git commit -m "v4.0.0: D1 storage via planner-api (test)"
git push
```

`git status` should not list `worker/.wrangler`; that folder is ignored on purpose. In the GitHub repo, open **Settings → Pages** and confirm it deploys from **main** / **(root)**. The site updates a minute or so after each push.

## 6. Sign in

Open https://zacharypals.github.io/Planner_Web_App_TEST/ and tap **Sign in with Google**. Approve both **Calendar** and **Drive**; Drive is used once, for the import in Phase 4. The nav bar should show **v4.0.0** with a **TEST** badge.

To let your family member use it, add their Gmail to `ALLOWED_EMAILS` in `worker\wrangler.toml` (comma-separated, e.g. `"znpals@gmail.com,their.name@gmail.com"`), then redeploy:

```powershell
cd "C:\Users\slapc\OneDrive\Documents\Personal\ProjectsVS\Planner_Tracker_D1\worker"
npx wrangler deploy
```

Their data is completely separate from yours.

---

## Future updates

Later zips are applied the same way:

```powershell
Expand-Archive -Path "C:\Users\slapc\OneDrive\Documents\Downloads\<zip name>.zip" -DestinationPath "C:\Users\slapc\OneDrive\Documents\Personal\ProjectsVS\Planner_Tracker_D1" -Force
```

Update zips do **not** include `worker/wrangler.toml`, so your database ID is never overwritten. Worker changes are deployed with `npx wrangler deploy` from the `worker` folder. Schema changes come as numbered files in `worker/migrations/` and are applied with `npx wrangler d1 migrations apply planner-db --remote`.

## Things worth trying

- Add a task on your laptop. "✓ Saved" should appear in about a second, and the task should show up on your phone within 30 seconds, or immediately when you switch back to the app.
- Edit the same week on both devices at about the same time. Both edits should survive. If you both changed the very same item, the device that saved last wins, and "⇄ Merged" appears briefly.
- Turn on airplane mode and make an edit. A "Changes not synced yet" toast appears and stays. Turn the connection back on and the toast clears by itself.
- Type in a Page, then immediately swipe the app away. Reopen it on another device and the text should be there.
- Sign out. The wall appears, and this app's data is removed from that browser. The live app's data is not touched.

## Running the tests (optional)

These need Node 22.5 or newer and nothing to install. Run from the repo root:

```powershell
cd "C:\Users\slapc\OneDrive\Documents\Personal\ProjectsVS\Planner_Tracker_D1"
node --test worker/test/worker.test.mjs worker/test/engine.test.mjs
```

## How it works (short version)

- **Sign-in:** Google proves who you are. `planner-api` then issues its own 90-day session, which renews as you use it. Your Google refresh token is stored encrypted in D1 and never leaves the Worker. The app receives only short-lived Calendar tokens.
- **Data:** your existing data shapes are stored unchanged, split into small documents: one per week, page, fitness day, and month of habit data, plus one per setting. Each save sends only the documents that changed.
- **Conflicts:** every save names the version it started from. If another device saved first, the two versions are merged field by field (and item by item for lists of tasks, habits, and so on).
- **Offline:** unsent edits wait in this browser's storage and upload automatically when you're back online, even after a restart.
- **New synced data:** create it with `useSynced(key, init)`. There's no list of keys to keep in sync anymore.
