# scopeward: Acme Corp (acme)

**Governance score: 81/100 (B)**

2 high · 1 info

## Human Identity

- **[HIGH]** Member has 2FA disabled  
  bob · `human.no-2fa`  
  Soft target.  
  _Fix:_ Enable 2FA.  

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
