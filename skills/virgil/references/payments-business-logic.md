# Payments, PCI-DSS v4.0, Concurrency & Business Logic Security

## 1. Payment Integration & PCI-DSS v4.0 Boundaries (Stripe / Shared Responsibility)
- `[RED]` **Raw Card Data (PAN/CVV) Touching App Servers (`CWE-312`):** Never accept, transmit, store, or log raw Primary Account Numbers (PANs), CVV/CVC codes, or magnetic-stripe data on your own backend. Use hosted/tokenized flows (**Stripe Checkout**, **Stripe Elements**, or provider mobile/Terminal SDKs) so card data flows directly from browser/device to the PCI Level 1 processor (preserving SAQ-A scope).
- `[RED]` **Client-Trusted Pricing, Currency or Discounts:** Never trust client-supplied `amount`, `price`, `currency`, `discount`, `tax`, or `plan_id` totals. Recompute all line items, taxes, and entitlements server-side from authoritative catalog/DB records before creating a payment intent or charge.
- `[RED]` **Over-Scoped Payment Keys & Unverified Webhooks:** Use least-privilege **restricted API keys** (`rk_live_`) scoped to exact resources instead of unrestricted secret keys (`sk_live_`) wherever supported, keep all secret/restricted keys strictly server-side, and verify payment webhook signatures (`Stripe-Signature` / HMAC-SHA256) over raw request body bytes in constant time.
- `[YELLOW]` **Payment-Page Script Integrity (PCI-DSS v4.0) & Anti-Carding:** Enforce Subresource Integrity (`integrity=`) and strict CSP monitoring on checkout/payment pages to prevent client-side skimming (Magecart). Enable fraud/velocity defenses (Stripe Radar, dynamic 3DS/SCA, tight rate limits on payment initiation) and pass deterministic **idempotency keys** on all charge/refund API calls.

## 2. Concurrency, Race Conditions & State-Machine Integrity
- `[RED]` **TOCTOU / Double-Spend Race Conditions (`CWE-362`, `CWE-367`):** Never perform non-atomic check-then-act mutations on balances, credits, coupons, gift cards, invites, or inventory (`SELECT balance` -> app `if balance >= amount` -> `UPDATE balance`). Enforce atomicity inside the database via:
  - Atomic conditional updates (`UPDATE accounts SET balance = balance - $1 WHERE id = $2 AND balance >= $1 RETURNING balance`), OR
  - Explicit pessimistic row locks (`SELECT ... FOR UPDATE`) inside a transaction, AND
  - Unique constraints on one-time redemptions (`UNIQUE(user_id, coupon_id)` / idempotency table).
- `[RED]` **Workflow / State-Machine Bypass:** Enforce allowed state transitions server-side (e.g., `draft -> paid -> fulfilled`, never `draft -> fulfilled` directly via direct endpoint call or webhook replay). Verify payment status directly with the processor or signed webhook event before granting entitlements.
- `[YELLOW]` **Numeric & Currency Precision Bugs:** Store and calculate monetary values in **integer minor units** (cents/kurus) or fixed-precision `DECIMAL`/`Numeric` types—never IEEE-754 floating-point (`float`/`double`). Reject `NaN`, `Infinity`, zero, and negative quantities/amounts at schema validation boundaries.

## Verification Checklist
- Grep logs, DTOs, and schemas to confirm zero raw card PAN/CVV fields touch backend handlers or logs.
- Replay checkout/order requests with mutated `amount: 1`, `quantity: -5`, or skipped payment step; assert server rejection.
- Execute parallel concurrent requests (e.g., 10 simultaneous requests redeeming the same coupon or withdrawing the same balance) to verify atomic DB locking prevents double-spend.
- Verify checkout HTML includes `integrity=` on any external `<script>` tags and payment API calls pass idempotency keys.

## Authoritative Sources
- [Stripe Security Integration Guide](https://docs.stripe.com/security/guide)
- [OWASP Top 10:2025 (A06 Insecure Design)](https://top10.owasp.org/2025/)
- [MITRE CWE-362 (Race Condition)](https://cwe.mitre.org/data/definitions/362.html) | [CWE-840 (Business Logic Errors)](https://cwe.mitre.org/data/definitions/840.html)
