---
name: business_logic
description: Logic flaws, state manipulation, race conditions
category: vulnerabilities
---

# Business Logic Testing

## Attack Surface
Business logic vulnerabilities exploit application workflow flaws rather than technical bugs.
- Multi-step flows that skip steps
- Coupon/discount abuse
- Race conditions in financial transactions
- State manipulation in wizards/checkouts
- Rate limiting bypass

## Methodology
1. **Workflow Bypass**
   - Skip verification/confirmation steps in multi-step flows
   - Directly access final step URLs
   - Manipulate step numbers/status fields in requests
   - Complete flows in unexpected order

2. **Race Conditions**
   - Send parallel requests for coupon redemption
   - Exploit time-of-check-to-time-of-use (TOCTOU) in financial operations
   - Concurrent login/session manipulation
   - Parallel voting/rating submission

3. **Price Manipulation**
   - Negative quantities in e-commerce
   - Integer overflow in price calculations
   - Currency conversion rounding abuse
   - Coupon stacking with no minimum

## Validation
- Successfully obtained item at reduced/invalid price
- Applied same coupon multiple times
- Accessed post-payment content without payment
- Completed flow bypassing critical security steps
- Race condition consistently reproducible
