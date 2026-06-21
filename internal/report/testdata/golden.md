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

## Not evaluated

- ~ Non-expiring PATs (`nonhuman.pat-no-expiry`): needs fine_grained_pats

## Coverage

- ✗ fine_grained_pats (org has not enabled the fine-grained PAT policy)
- ✓ members
