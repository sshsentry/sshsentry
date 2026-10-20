# Publishing sshsentry to PyPI

Chris does these steps himself. Nothing has been uploaded yet.

1. **Create a PyPI account** at https://pypi.org/account/register/ with `sshsentry@gmail.com`, then verify the email.
2. **Turn on 2FA** under Account settings → Two factor authentication (an authenticator app or a security key). PyPI requires it before you can upload.
3. **Create an API token** under Account settings → API tokens → Add API token. For the first upload the scope has to be "Entire account", because the project doesn't exist yet. Copy the token (`pypi-...`). It's shown only once.
4. **(Optional) Try TestPyPI first.** It's a separate site with a separate account and token: https://test.pypi.org/account/register/
   ```bash
   /tmp/sentvenv/bin/twine upload --repository testpypi dist/*
   python3 -m venv /tmp/tp && /tmp/tp/bin/pip install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ sshsentry
   /tmp/tp/bin/sshsentry --help
   ```
5. **Upload to PyPI** from this folder:
   ```bash
   cd /workspace/sshsentry
   /tmp/sentvenv/bin/twine check dist/*
   /tmp/sentvenv/bin/twine upload dist/*
   ```
   Username: `__token__`. Password: the API token.
6. **After the first upload**, go back to Account settings → API tokens. Replace the account-wide token with one scoped to the `sshsentry` project only, and delete the old one.

To rebuild (for example after bumping `version` in `pyproject.toml`; PyPI never accepts the same version twice):
```bash
rm -rf dist && /tmp/sentvenv/bin/python -m build && /tmp/sentvenv/bin/twine check dist/*
```
