# Setting up GitHub Discussions for sshsentry

Do this once the GitHub repo exists. It takes about 5 minutes.

1. **Push the repo** with the `.github/DISCUSSION_TEMPLATE/` folder on the default branch. The forms only load from the default branch.
2. **Enable Discussions:** go to the repo's **Settings → General → Features** and tick **Discussions**.
3. **Create the categories:** open the **Discussions** tab, click the pencil next to **Categories**, then **New category**:
   - **Configs**: slug **`share-config`**, format *Open-ended discussion*. Description: "Share your thresholds and learn-mode suggestions (redact secrets)."
   - **Attack patterns**: slug **`attack-pattern`**, format *Open-ended discussion*. Description: "Patterns sshsentry caught or missed, with counts and mitigations."
   
   A form only applies when the category slug matches its file name (`share-config.yml` → `share-config`, `attack-pattern.yml` → `attack-pattern`). If GitHub creates a different slug from the name, edit the category slug, or rename the file to match.
4. **Optional labels:** create the labels `config` and `attack-pattern` (**Issues → Labels**). The forms apply them automatically.
5. **Update the README:** replace `<owner>` in `https://github.com/<owner>/sshsentry/discussions` with your GitHub user or org name.
6. **Check it:** start a new discussion in each category and confirm the form fields and privacy checkbox appear. Delete the test posts afterwards.
7. **Optional:** pin a welcome post in each category that repeats the privacy reminder, and remove default categories you don't want, such as Polls or Show and tell.
