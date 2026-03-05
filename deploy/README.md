# Production deploy (local rules)

Create a local rules file:

- Copy `deploy/production.rules.example.json` → `deploy/production.rules.json`
- Edit as needed (region/domain/emails, etc.)

`deploy/production.rules.json` is ignored by git so you can keep local overrides without committing them.

Deploy script:

- `scripts/deploy_production.ps1`

