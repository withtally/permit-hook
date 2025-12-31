# Security Audit Report - Permitter Smart Contract System

**Audit Date:** 2025-12-31
**Auditor:** Claude Code Security Review
**Status:** FINAL REPORT
**Commit:** 54f913c (main branch)

---

## Executive Summary

This report presents findings from a comprehensive security audit of the Permitter smart contract system. The Permitter implements a validation hook for Uniswap CCA (Continuous Combinatorial Auction) that enforces KYC-based permissions using EIP-712 signed permits.

### Contracts Audited

| Contract | Lines | Purpose |
|----------|-------|---------|
| Permitter.sol | 183 | Core validation hook |
| PermitterFactory.sol | 57 | CREATE2 factory |
| IPermitter.sol | 150 | Interface |
| IPermitterFactory.sol | 51 | Factory interface |

### Finding Summary

| Severity | Count | Key Issues |
|----------|-------|------------|
| **Critical** | 1 | Owner DoS via zero caps |
| **High** | 3 | TOCTOU race conditions, no cap validation, state invariant violations |
| **Medium** | 4 | No caller validation, signer rotation issues, no ownership transfer |
| **Low** | 2 | Zero-amount bids, unlimited permit expiry |
| **Informational** | 3 | Trust assumptions, MEV exposure, gas optimization |

**Overall Risk:** MEDIUM-HIGH (reducible to LOW with recommended fixes)

---

## Critical Findings

### [C-01] Owner Can DoS Auction via Zero Caps

**Severity:** Critical
**Location:** `Permitter.sol:120-131`
**PoC:** `ExploitTests.t.sol::testExploit_OwnerDoSViaZeroCaps`

**Description:** Owner can set `maxTotalEth` or `maxTokensPerBidder` to zero at any time, permanently blocking all bids.

```solidity
function updateMaxTotalEth(uint256 newMaxTotalEth) external onlyOwner {
    maxTotalEth = newMaxTotalEth; // No validation - accepts 0
}
```

**Impact:** Malicious or compromised owner can halt entire auction permanently.

**Recommendation:** Add minimum cap validation:
```solidity
if (newMaxTotalEth == 0) revert InvalidCap();
if (newMaxTotalEth < totalEthRaised) revert CapBelowCurrentAmount();
```

---

## High Findings

### [H-01] TOCTOU Race Conditions in Parameter Updates

**Severity:** High
**Location:** `Permitter.sol:98-100, 105, 85` vs `120-138`
**PoC:** `ExploitTests.t.sol::testExploit_TOCTOUFrontRun`

**Description:** Owner can front-run pending bids by updating caps or rotating the trusted signer between validation and state update.

**Impact:**
- Selective bid censorship via cap manipulation
- All permits invalidated instantly on signer rotation
- Unfair auction participation

**Recommendation:** Implement timelock for parameter updates (minimum 1 hour delay).

### [H-02] State Invariant Violation via Cap Reduction

**Severity:** High
**Location:** `Permitter.sol:120-131`
**PoC:** `ExploitTests.t.sol::testExploit_StateInvariantViolation`

**Description:** Owner can reduce caps below already-committed amounts, creating invalid state where `totalEthRaised > maxTotalEth`.

**Impact:** Auction enters permanent DoS state - no new bids possible.

**Recommendation:** Validate `newMaxTotalEth >= totalEthRaised` before update.

### [H-03] No Constructor Parameter Validation

**Severity:** High
**Location:** `Permitter.sol:50-63`
**PoC:** `ExploitTests.t.sol::testExploit_ConstructorZeroCaps`

**Description:** Constructor accepts zero values for caps, resulting in unusable deployment.

**Recommendation:** Add constructor validation for non-zero caps.

---

## Medium Findings

### [M-01] No Caller Validation on validateBid

**Severity:** Medium
**Location:** `Permitter.sol:66`
**PoC:** `ExploitTests.t.sol::testExploit_NoCallerValidation`

**Description:** Any address can call `validateBid()`, not just the CCA contract. Attackers can manipulate bid state if they obtain permit data.

**Recommendation:** Add authorized caller whitelist:
```solidity
address public immutable authorizedCaller;
if (msg.sender != authorizedCaller) revert UnauthorizedCaller();
```

### [M-02] Instant Permit Invalidation via Signer Update

**Severity:** Medium
**Location:** `Permitter.sol:134-139`
**PoC:** `ExploitTests.t.sol::testExploit_SignerRotationInvalidatesPermits`

**Description:** Updating `trustedSigner` instantly invalidates all existing permits with no grace period.

**Recommendation:** Implement grace period mechanism allowing both old and new signer during transition.

### [M-03] No Ownership Transfer Mechanism

**Severity:** Medium
**Location:** `Permitter.sol:34`
**PoC:** `ExploitTests.t.sol::testExploit_NoOwnershipTransfer`

**Description:** Owner address is immutable after deployment. Key loss results in permanent lockout.

**Recommendation:** Add two-step ownership transfer pattern.

### [M-04] Unbounded Pause Duration

**Severity:** Medium
**Location:** `Permitter.sol:142-151`
**PoC:** `ExploitTests.t.sol::testExploit_UnboundedPause`

**Description:** No automatic unpause or governance override exists. Owner can pause indefinitely.

**Recommendation:** Add pause expiry or governance override mechanism.

---

## Low Findings

### [L-01] Zero-Amount Bids Accepted

**Severity:** Low
**Location:** `Permitter.sol:92-105`

**Description:** `bidAmount = 0` and `ethValue = 0` pass validation, polluting event logs.

### [L-02] No Maximum Permit Expiry

**Severity:** Low
**Location:** `Permitter.sol:79`

**Description:** Permits can have unlimited expiry (`type(uint256).max`), violating KYC re-verification requirements.

---

## Informational

### [I-01] CCA Contract Trust Assumptions

The Permitter trusts the CCA contract to pass correct `bidAmount` and `ethValue` parameters. This contract was not provided for review.

### [I-02] MEV Exposure

First-come-first-served cap enforcement creates MEV opportunities. Consider Flashbots Protect or batch auctions.

### [I-03] No State Reset Mechanism

`cumulativeBids` and `totalEthRaised` persist permanently. Deploy new Permitter for each auction.

---

## Proof of Concept Tests

All 8 exploit PoCs pass:

```
forge test --match-contract ExploitTests -vv

[PASS] testExploit_OwnerDoSViaZeroCaps()
[PASS] testExploit_StateInvariantViolation()
[PASS] testExploit_TOCTOUFrontRun()
[PASS] testExploit_SignerRotationInvalidatesPermits()
[PASS] testExploit_NoCallerValidation()
[PASS] testExploit_ConstructorZeroCaps()
[PASS] testExploit_NoOwnershipTransfer()
[PASS] testExploit_UnboundedPause()
```

---

## Recommendations Summary

### Critical Priority (Fix Before Production)

1. **Add cap update validation** - Prevent zero caps and retroactive violations
2. **Implement timelock** - 1-hour delay for cap/signer updates
3. **Validate constructor parameters** - Require non-zero caps

### High Priority

4. **Add CCA caller whitelist** - Restrict `validateBid()` to authorized caller
5. **Implement signer grace period** - Allow transition time for signer rotation
6. **Add ownership transfer** - Two-step transfer pattern

### Medium Priority

7. **Reject zero-amount bids**
8. **Enforce maximum permit lifetime** (e.g., 365 days)
9. **Add pause expiry mechanism**

### Operational

10. **Audit CCA contract** - Validate trust assumptions
11. **Use multisig for owner** - Reduce key compromise risk
12. **Set up monitoring** - Track `CapUpdated` and `SignerUpdated` events

---

## Good Practices Observed

- Solidity 0.8.30 with built-in overflow protection
- Custom errors for gas efficiency
- EIP-712 signature verification
- OpenZeppelin library usage
- Comprehensive event emissions
- NatSpec documentation

---

## Conclusion

The Permitter system demonstrates professional code quality but has critical and high-severity issues requiring remediation before production deployment. The most critical concern is owner privilege abuse potential through cap manipulation and signer rotation.

**Recommended Next Steps:**
1. Implement all Critical/High fixes
2. Audit Uniswap CCA contract
3. Re-audit after fixes
4. Deploy to testnet for operational validation
5. Proceed to mainnet with monitoring

---

**Report Version:** 1.0 FINAL
**Generated:** 2025-12-31
**Auditor:** Claude Code Security Review
