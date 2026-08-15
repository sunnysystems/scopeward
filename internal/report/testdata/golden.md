# scopeward: Acme Corp (acme)

**Governance score: 35/100 (F)**

_penalty 183 · 12 not instrumented, 171 open findings · 15.9 per repo across 4 repos_

_the previous scoring model gave 53 (D); per-repo penalty is now a rate, so the number no longer tracks org size_

1 critical · 2 high · 1 medium · 1 info

## Human Identity

- **[HIGH]** Member has 2FA disabled  
  bob · `human.no-2fa`  
  Soft target.  
  _Fix:_ Enable 2FA.  

## Code Security

- **[CRITICAL]** acme/api has 42 open Dependabot alert(s)  
  acme/api · `codesecurity.open-dependabot-alerts`  
  Known-vulnerable dependencies.  
- **[MEDIUM]** Push protection is off on acme/api  
  acme/api · `codesecurity.repo-no-push-protection`  
  Secrets are only caught after the push.  

## AI Agents

- **[HIGH]** Agent commits with broad write  
  ai-refactor[bot] · `ai.agent-broad-write`  
  Big blast radius.  
- **[INFO]** 3 machine identities committed code  
  acme · `ai.agent-inventory`  
  Inventory.  

## Partially evaluated

- ~ Repos without push protection (`codesecurity.repo-no-push-protection`): assessed 3, 39 not assessed — private repositories require GitHub Secret Protection, which this organization does not have

## Not evaluated

- ~ Non-expiring PATs (`nonhuman.pat-no-expiry`): needs fine_grained_pats

## Coverage

- ✗ fine_grained_pats (org has not enabled the fine-grained PAT policy)
- ✓ members
