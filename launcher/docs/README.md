# docs/

Documentation for the launcher. Audience is split: operators (deploy
the image), auditors (verify the image), and reviewers (understand the
threat model).

## Documents

| Document | Audience | Purpose |
|---|---|---|
| `architecture.md` | All | Overall launcher architecture, component diagram, boot flow |
| `operator-guide.md` | Validator operators | Deploy steps, daily ops, upgrade flow |
| `threat-model.md` | Reviewers / governance | A/B/B'/C/D threat model and which component defends each |

## Why a dedicated threat-model document

The launcher's existence is driven by the threat model. Without a
single canonical statement of *what we protect against and why*, every
sub-component drifts (image hardening, attestation choice,
platform_commitment scope, etc.). `threat-model.md` is the source of
truth that every other component justifies itself against.
