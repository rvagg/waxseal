# Waxseal

Publish a prepared npm tarball or Rust crate to its registry and attach the same file to an immutable GitHub release. Run Waxseal from a `vMAJOR.MINOR.PATCH` tag and pin the action to a reviewed commit.

## Workflow setup

Build, test and pack in a job with `contents: read` permissions. Upload the package file as `release-files-RUN_ID-RUN_ATTEMPT`, which is the default `artifact-name`. `package-directory` defaults to `.` and points to the package manifest and `CHANGELOG.md`.

Use a separate GitHub-hosted Ubuntu job for publishing, with Waxseal as its only step. Give it the `release` environment, a 45-minute timeout, and `contents: write`, `id-token: write` and `attestations: write` permissions. Protect release tags and enable immutable GitHub releases.

Configure the registry's trusted publisher for your calling workflow and its `release` environment.

## npm

Use the root `rvagg/waxseal` action and upload a single `.tgz` from the build job. Waxseal reads the name, version and release notes from the tagged checkout, checks the archive's package metadata, and publishes it using Node 26 and npm with `--ignore-scripts`.

Allow direct `npm publish` in the npm trusted-publisher settings.

## Rust

Use `rvagg/waxseal/crates` for a single package made with Cargo 1.83 or newer. Run `cargo package` in the build job and upload `NAME-VERSION.crate` as the artifact's only file, at its root. Add `actions: read` to the publishing job. Custom artifact names must start with a letter or digit and contain only ASCII letters, digits, dots, underscores or hyphens.

Waxseal checks the artifact's workflow run and size, then reads the crate from its ZIP. It compares `Cargo.toml.orig`, the packaged manifest's settings and target paths, the README contents and the recorded Git commit with the tagged checkout. Python uploads that `.crate` directly to the crates.io API.

Include every explicitly declared target in the package. Workspaces, `patch`/`replace` overrides, and git, path or alternative-registry dependencies aren't supported.

## Publication checks and failures

Waxseal records the archive's hash, workflow and commit in a GitHub attestation. It checks the registry's copy against that hash before publishing the GitHub release. To check reproducibility, rebuild the tagged source and compare the archives.

Waxseal retries registry reads for up to five minutes. Metadata, authentication, certificate and checksum errors stop the action. Uploads and GitHub writes are attempted once.

If publication stops part-way through, inspect the registry version and GitHub draft. If the package is already published, keep the draft and archive, verify their contents, and finish that release manually. Rerunning Waxseal stops when it finds an existing version, draft or release.

Apache-2.0. Copyright 2026 Rod Vagg.
