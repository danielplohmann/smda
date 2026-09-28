<!--
The PR *title* must be a conventional commit: `type(scope): summary`.
Types and scopes are the lists in .github/workflows/semantic-pr-title.yml, and CI enforces them.
-->

## What this changes

## How it was verified

<!--
Commands, and what they said. For anything touching recovery, escaping or hashing: name the
corpus a claim was measured on and what the change cost, the way CHANGELOG.md asks for.
-->

- [ ] `make lint` and `make format`
- [ ] `make test-all`
- [ ] `CHANGELOG.md` entry under `## [Unreleased]`, or the `no-changelog` label with a reason
- [ ] Golden fixtures unchanged — or the baseline move is deliberate and explained above

Closes #
