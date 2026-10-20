# GitHub repo + Pages setup for sshsentry

You do all of these steps yourself. Nothing has been pushed. The local repo in this folder is on branch `main` and has one initial commit. `dist/` is not in git.

## 1. Create the repo
Signed in as **sshsentry** on GitHub, go to https://github.com/new and create:
- Owner/name: `sshsentry/sshsentry`
- Visibility: **Public**
- **Empty**: leave all three boxes unticked (no README, no .gitignore, no license), because those files already exist here.

## 2. Push
Using the gh CLI (log in first with `gh auth login`):
```bash
cd /workspace/sshsentry
git remote add origin https://github.com/sshsentry/sshsentry.git
git push -u origin main
```
gh can also create and push in one step: `gh repo create sshsentry/sshsentry --public --source=. --remote=origin --push`

## 3. Turn on Pages
Go to Repo → **Settings → Pages → Build and deployment → Source: GitHub Actions**.
After that, the workflow `.github/workflows/pages.yml` publishes `demo/` (index.html, images, CNAME) whenever something under `demo/` changes on `main`. To run it now, go to **Actions → Deploy demo to GitHub Pages → Run workflow**.

## 4. Verify the domain (recommended, do it before step 6)
This stops anyone else from claiming sshsentry.com on GitHub Pages.
1. Open your profile **Settings → Pages → Add a domain**, enter `sshsentry.com`.
2. GitHub shows a TXT record: name `_github-pages-challenge-sshsentry`, plus a value. Add it at WordPress.com (step 5).
3. Click **Verify**. DNS can take a while to update.

## 5. DNS records at WordPress.com for sshsentry.com
Go to WordPress.com → **Upgrades → Domains → sshsentry.com → DNS records → Add a record**.
Delete any default A/AAAA records that point at WordPress hosting, or records on `www` that conflict with the ones below.

| Type  | Name / Host | Value                   |
|-------|-------------|-------------------------|
| A     | @ (root)    | 185.199.108.153         |
| A     | @           | 185.199.109.153         |
| A     | @           | 185.199.110.153         |
| A     | @           | 185.199.111.153         |
| AAAA  | @           | 2606:50c0:8000::153     |
| AAAA  | @           | 2606:50c0:8001::153     |
| AAAA  | @           | 2606:50c0:8002::153     |
| AAAA  | @           | 2606:50c0:8003::153     |
| CNAME | www         | sshsentry.github.io     |
| TXT   | _github-pages-challenge-sshsentry | (value from step 4) |

To check: `dig +short sshsentry.com A`, `dig +short sshsentry.com AAAA`, `dig +short www.sshsentry.com`

## 6. Custom domain + HTTPS
Go to Repo → **Settings → Pages → Custom domain**, enter `sshsentry.com`, and click **Save**. Wait for the DNS check to pass, then tick **Enforce HTTPS**. The certificate can take up to about an hour to issue.
When Pages is deployed with GitHub Actions, the custom domain is controlled by this setting. The `demo/CNAME` file is included only for consistency.

## 7. Optional: forward sshsentry.dev and sshsentry.org
For each of the two domains, go to WordPress.com → **Domains → (domain) → Forwarding** (sometimes called "Domain forwarding" or "Redirect"). Forward to `https://sshsentry.com`, and make it permanent (301) if WordPress.com offers the choice.
