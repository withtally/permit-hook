# Phase 4: State Walk - Permitter.sol Security Audit

**Date**: 2025-12-31
**Contract**: `/src/Permitter.sol`
**Methodology**: Line-by-line state tracking with adversarial questioning

## Executive Summary

8 critical and high-severity findings identified through systematic state tracking.

## Critical Findings

### 1. TOCTOU Vulnerabilities - HIGH
**Location**: Lines 98-100, 105, 85 vs update functions at 122, 129, 137
Owner can front-run validateBid() by updating caps/signer between validation and state updates.

### 2. No Constructor Parameter Validation - HIGH
**Location**: Lines 60-61
Constructor accepts maxTotalEth=0 or maxTokensPerBidder=0 without validation.

### 3. No Cap Update Validation - HIGH
**Location**: Lines 122, 129
Owner can set caps below already-committed amounts.

### 4. Instant Permit Invalidation - MEDIUM
**Location**: Line 137
Updating trustedSigner instantly invalidates all in-flight permits.

### 5. No bidAmount/ethValue Correlation - MEDIUM
**Location**: Lines 92, 104
Contract tracks tokens and ETH independently without validating relationship.

### 6. Zero-Amount Bids Allowed - LOW
**Location**: Lines 92-105
bidAmount=0 and ethValue=0 passes all validation.

### 7. Permanent Permits Possible - LOW
**Location**: Line 79
No maximum limit on permit.expiry.

### 8. No EOA Validation for newSigner - MEDIUM
**Location**: Lines 135-137
updateTrustedSigner() allows contract addresses (which can't sign).

## State Invariants

### Maintained ✓
- Monotonically increasing cumulativeBids/totalEthRaised
- Overflow protection (Solidity 0.8.30)
- Permit ownership verification
- EIP-712 signature verification

### Broken ✗
- maxTotalEth >= totalEthRaised (owner can violate)
- maxTokensPerBidder >= cumulativeBids (owner can violate retroactively)
- Atomic cap enforcement (TOCTOU)
- Current trustedSigner validation (TOCTOU)
- bidAmount/ethValue correlation (no validation)
- Non-zero bid amounts (zero bids accepted)

## Recommendations
1. Add reentrancy guards (defense-in-depth)
2. Validate constructor parameters: Require caps > 0
3. Validate cap updates: Require newMaxTotalEth >= totalEthRaised
4. Add minimum bid amounts
5. Implement timelock on critical parameter updates
6. Add grace period for signer updates
7. Validate newSigner is EOA (extcodesize == 0)
8. Cap maximum permit expiry
