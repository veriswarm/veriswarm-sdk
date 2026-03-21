# SDK Publishing via GitHub CI

Both SDKs publish automatically via GitHub Actions when you push a version tag.

## npm (`@veriswarm/sdk`)

### One-time setup

1. Go to [npmjs.com](https://www.npmjs.com) → create an org called `veriswarm` if not done
2. Generate an access token: npm → Account → Access Tokens → Generate New Token (Automation)
3. Add it as a repo secret: GitHub → `veriswarm-sdk` repo → Settings → Secrets → Actions → New secret → name: `NPM_TOKEN`, value: your token

### To publish

```bash
cd ~/veriswarm-sdk
git tag node-v0.2.0
git push origin node-v0.2.0
```

The workflow triggers automatically and publishes `@veriswarm/sdk@0.2.0` to npm.

## PyPI (`veriswarm`)

### One-time setup (trusted publishing — no API token needed)

1. Go to [pypi.org](https://pypi.org) → create your account
2. Go to your account → Publishing → Add a new pending publisher:
   - **PyPI project name**: `veriswarm`
   - **Owner**: `JoshuaAFerguson`
   - **Repository**: `veriswarm-sdk`
   - **Workflow name**: `publish-python.yml`
   - **Environment**: *(leave blank)*
3. Submit

### To publish

```bash
cd ~/veriswarm-sdk
git tag python-v0.2.0
git push origin python-v0.2.0
```

The workflow triggers automatically and publishes `veriswarm==0.2.0` to PyPI using OIDC trusted publishing (no API key needed).

## Future releases

1. Update the version in `node/package.json` or `python/pyproject.toml`
2. Commit the version bump
3. Tag and push:

```bash
git tag node-v0.3.0    # for Node
git tag python-v0.3.0  # for Python
git push origin --tags
```

## Manual trigger

Both workflows also support `workflow_dispatch` — you can trigger them manually from the GitHub Actions tab without creating a tag.
