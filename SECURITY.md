# Security policy

heldkeys reads credentials so that it can tell you about them. A bug that makes it leak one is the most serious kind of bug it can have, and reports are welcome.

## Reporting a vulnerability

Please report privately through GitHub: open the [Security tab](https://github.com/hugomn/heldkeys/security) and choose **Report a vulnerability**, or go straight to the [new advisory form](https://github.com/hugomn/heldkeys/security/advisories/new). Do not open a public issue or pull request for a vulnerability.

Include what you ran, on which platform, and what you saw. A fixture that reproduces it is ideal. Use fake credentials only: never send a real secret, not even an expired one.

You can expect an acknowledgement within 5 days and a first assessment within 14. heldkeys is maintained by one person, outside working hours, so please allow for that. Fixes are released as soon as they are ready, and the advisory credits you unless you prefer otherwise.

## What counts

Anything that breaks one of the promises in the README or the [threat model](docs/threat-model.md), for example:

- a secret value, or more than 4 leading and 3 trailing characters of one, reaching stdout, stderr, a log, or a `--output` file in any format;
- a network connection the documentation does not describe, or one made without `--deep` that touches a credential;
- heldkeys writing, modifying or deleting anything other than the file named with `--output`;
- heldkeys running any program other than `ssh-add -l`, `git ls-files` (with `ci --repo-secrets`), or `docker` and `kubectl` (with `scan --docker` or `--kube`);
- text from a scanned file or a container reaching the output in a form that does something: a terminal escape, a GitHub Actions workflow command, rendered Markdown or HTML;
- a crafted config file (kubeconfig, MCP config, workflow, `.env`, ...) that makes heldkeys crash, hang, read outside the paths it documents, or execute anything;
- the release binaries or the GitHub Action doing something other than what their source says.

Missed credentials and wrong severities are bugs, not vulnerabilities: please open a normal issue for those.

## Supported versions

Only the latest release receives security fixes.
