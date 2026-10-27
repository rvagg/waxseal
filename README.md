# Waxseal

Composite GitHub Action for source-bound npm publishing and immutable GitHub releases. Pin the action to a reviewed commit.

Build, test and pack in a separate job. Upload only the `.tgz` as `release-files-RUN_ID-RUN_ATTEMPT`; override `artifact-name` if needed. `package-directory` defaults to `.` and contains `package.json` and `CHANGELOG.md`. Identity and notes come from the approved tag, not the artifact.

Use a fresh GitHub-hosted Ubuntu publishing job with no preceding project code, installs, tests, executable caches or unreviewed actions. Waxseal sets up Node 26. The job needs environment `release`, a 45-minute timeout, and `contents`, `id-token` and `attestations` write permissions. Protect release tags, enable immutable releases, and bind npm trusted publishing to the caller workflow/environment with direct `npm publish` allowed.

No package lifecycle scripts run during publication. Partial npm/GitHub failures stop for owner inspection; existing releases are never overwritten.

Apache-2.0. Copyright 2026 Rod Vagg.
