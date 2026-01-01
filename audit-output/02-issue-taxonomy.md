# Phase 2: Issue Taxonomy
**Permitter Smart Contract System**

**Audit Date:** 2025-12-31
**Auditor:** Security Review Team
**Codebase:** `/Users/rafael/conductor/workspaces/permit-hook/boise/src/`

---

## OVERVIEW

This taxonomy defines the universe of potential security issues to investigate during the deep-dive audit phase. Each category is scored for relevance (1-5) based on Phase 1 reconnaissance findings, with specific contracts and functions flagged for detailed analysis.

**Scoring Legend:**
- **5 = Critical Priority** - High likelihood and/or high impact
- **4 = High Priority** - Moderate-high likelihood or impact
- **3 = Medium Priority** - Present in codebase, requires investigation
- **2 = Low Priority** - Limited exposure, edge cases
- **1 = Minimal Priority** - Unlikely or not applicable

---

## 1. REENTRANCY VARIANTS

**Relevance Score: 2/5** (Low Priority)

### Rationale
The Permitter contracts make no external calls to untrusted contracts. The only external interaction is with OpenZeppelin's ECDSA library (view-only, no state changes). However, the CCA contract (caller) is not in scope and represents an unknown.

### Check Items

#### 1.1 Classic Reentrancy (CEI Pattern Violations)
- **Location:** `Permitter.sol::validateBid()` (lines 66-117)
- **Risk:** Low - no external calls to untrusted contracts
- **Action Items:**
  - [ ] Verify state updates occur AFTER all external calls
  - [ ] Confirm storage writes at lines 108-109 are safe
  - [ ] Validate that ECDSA.recover (line 181) cannot trigger callbacks

#### 1.2 Cross-Function Reentrancy
- **Location:** All state-changing functions in `Permitter.sol`
- **Risk:** Minimal - no function calls other functions that could be re-entered
- **Action Items:**
  - [ ] Map all function interaction patterns
  - [ ] Verify no circular call paths exist
  - [ ] Check if owner functions can be called during `validateBid` execution

#### 1.3 Read-Only Reentrancy
- **Location:** View functions exposing state (`getBidAmount`, `getTotalEthRaised`)
- **Risk:** Low - external protocols reading state mid-transaction could get stale data
- **Action Items:**
  - [ ] Identify if external protocols depend on these view functions
  - [ ] Check if CCA contract reads state during bid validation
  - [ ] Verify no view functions are called during state transitions

#### 1.4 Cross-Contract Reentrancy
- **Location:** CCA contract calling `validateBid`
- **Risk:** Medium - CCA contract behavior is unknown
- **Action Items:**
  - [ ] Document assumed CCA contract call patterns
  - [ ] Verify Permitter state cannot be exploited if CCA re-enters
  - [ ] Check if multiple Permitter instances can interfere with each other

---

## 2. ACCESS CONTROL

**Relevance Score: 5/5** (Critical Priority)

### Rationale
Owner role has significant privileges (pause, update caps, rotate signer). No ownership transfer mechanism. Trusted signer controls all permit issuance. This is a critical attack surface.

### Check Items

#### 2.1 Owner Privilege Abuse
- **Location:** All `onlyOwner` functions (lines 120-151)
- **Risk:** HIGH - Single point of failure, no timelock
- **Action Items:**
  - [ ] Test owner setting `maxTotalEth` to 0 (DoS attack)
  - [ ] Test owner setting `maxTokensPerBidder` to type(uint256).max (bypass caps)
  - [ ] Analyze front-running scenarios where owner changes caps mid-auction
  - [ ] Verify no way to rescue mistakenly set values
  - [ ] Check for rug-pull vectors via pause + parameter manipulation
  - [ ] Test impact of changing caps while bids are in flight

#### 2.2 Missing Access Controls
- **Location:** `validateBid()` function (line 66)
- **Risk:** MEDIUM - Anyone can call, relies on CCA contract to gate access
- **Action Items:**
  - [ ] Verify CCA contract properly gates access to `validateBid`
  - [ ] Test if malicious contracts can call `validateBid` directly
  - [ ] Check if there should be caller whitelist
  - [ ] Analyze impact of arbitrary addresses calling with crafted parameters

#### 2.3 Ownership Transfer / Renunciation
- **Location:** Constructor (lines 50-63) - owner set immutably
- **Risk:** HIGH - No emergency ownership transfer
- **Action Items:**
  - [ ] Verify owner loss-of-key scenario cannot be recovered
  - [ ] Check if owner address can be a contract that self-destructs
  - [ ] Test setting owner to dead address (griefing)
  - [ ] Document operational risks of immutable ownership

#### 2.4 Modifier Security
- **Location:** `onlyOwner` modifier (lines 40-43)
- **Risk:** LOW - Simple implementation
- **Action Items:**
  - [ ] Verify modifier cannot be bypassed via delegatecall (N/A - no delegatecall)
  - [ ] Check for function signature collisions
  - [ ] Test modifier with address(0) as owner edge case

#### 2.5 Trusted Signer Key Management
- **Location:** `trustedSigner` state variable (line 19)
- **Risk:** CRITICAL - Compromise = total system failure
- **Action Items:**
  - [ ] Document key rotation procedure via `updateTrustedSigner`
  - [ ] Test impact of rotating signer mid-auction (invalidates all permits)
  - [ ] Verify permits cannot outlive signer rotation
  - [ ] Check if setting trustedSigner to owner creates conflict of interest
  - [ ] Analyze multi-signer scenarios (current design doesn't support)

---

## 3. ARITHMETIC

**Relevance Score: 3/5** (Medium Priority)

### Rationale
Solidity 0.8.30 has built-in overflow protection, but edge cases and business logic errors still possible. Multiple addition operations track cumulative values.

### Check Items

#### 3.1 Integer Overflow/Underflow
- **Location:** Lines 92, 104 (cumulative additions)
- **Risk:** LOW - Solidity 0.8.30 reverts on overflow
- **Action Items:**
  - [ ] Test with type(uint256).max values
  - [ ] Verify overflow reverts are acceptable behavior (not DoS)
  - [ ] Check if caps should enforce reasonable bounds to prevent overflow scenarios
  - [ ] Test: `alreadyBid + bidAmount` overflow
  - [ ] Test: `alreadyRaised + ethValue` overflow

#### 3.2 Precision Loss / Rounding Errors
- **Location:** N/A - No division operations
- **Risk:** MINIMAL - No math requiring precision
- **Action Items:**
  - [ ] Confirm no hidden division in dependencies
  - [ ] Verify calculations are exact (no approximations)

#### 3.3 Logical Arithmetic Errors
- **Location:** Cap comparison logic (lines 93-105)
- **Risk:** MEDIUM - Business logic could allow bypass
- **Action Items:**
  - [ ] Test boundary conditions: `newCumulative == permit.maxBidAmount`
  - [ ] Test boundary conditions: `newCumulative == maxTokensPerBidder`
  - [ ] Test boundary conditions: `newTotalEth == maxTotalEth`
  - [ ] Verify strict inequality (>) vs >= is correct (line 79, 93, 98, 105)
  - [ ] Check if 0 values are handled correctly (0 bid amount, 0 eth value)

#### 3.4 Cumulative Tracking Integrity
- **Location:** `cumulativeBids` mapping (line 28), `totalEthRaised` (line 31)
- **Risk:** HIGH - Data can never be reset
- **Action Items:**
  - [ ] Test what happens if auction fails and needs restart
  - [ ] Verify no mechanism to decrement cumulative values (refunds)
  - [ ] Check if bids can be canceled in CCA contract (state becomes stale)
  - [ ] Analyze impact of permanent state accumulation

---

## 4. ORACLE MANIPULATION

**Relevance Score: 1/5** (Minimal Priority)

### Rationale
No price oracles, no external data feeds. All validation based on on-chain signatures and parameters. However, the "oracle" here is the trusted signer (off-chain KYC).

### Check Items

#### 4.1 Price Oracle Attacks
- **Location:** N/A
- **Risk:** N/A - No oracles used
- **Action Items:**
  - [ ] Confirm no hidden price dependencies

#### 4.2 Off-Chain Data Integrity (Trusted Signer as "Oracle")
- **Location:** `trustedSigner` signs permits off-chain
- **Risk:** MEDIUM - Signer is the source of truth for KYC
- **Action Items:**
  - [ ] Document how signer determines `maxBidAmount` values
  - [ ] Verify no way to manipulate permit issuance (social engineering)
  - [ ] Check if multiple permits can be issued for same user with different caps
  - [ ] Analyze permit issuance process for centralization risks
  - [ ] Test impact of signer issuing malicious permits (overly high caps)

#### 4.3 Timestamp Manipulation
- **Location:** `block.timestamp` used for expiry check (line 79)
- **Risk:** LOW - Miners can manipulate by ~15 seconds
- **Action Items:**
  - [ ] Test if 15-second timestamp drift enables exploits
  - [ ] Verify expiry logic: `block.timestamp > permit.expiry` (strictly greater)
  - [ ] Check edge case: expiry = block.timestamp (permit just expired)
  - [ ] Analyze if validators can game permit expiry windows

---

## 5. TIMING & ORDERING (MEV)

**Relevance Score: 4/5** (High Priority)

### Rationale
Auction mechanics are susceptible to front-running, back-running, and sandwich attacks. Owner can change caps mid-auction. First-come-first-served cap enforcement creates MEV opportunities.

### Check Items

#### 5.1 Front-Running Attacks
- **Location:** `validateBid()` function (line 66)
- **Risk:** HIGH - Bids compete for limited cap space
- **Action Items:**
  - [ ] Test scenario: Alice sees Bob's pending bid, front-runs to fill remaining cap
  - [ ] Analyze if MEV bots can monitor mempool for permits and front-run
  - [ ] Check if commit-reveal scheme would be beneficial
  - [ ] Verify permit expiry doesn't enable front-running exploits
  - [ ] Test: Does ordering of same-block bids matter?

#### 5.2 Back-Running Attacks
- **Location:** Cap update functions (lines 120-131)
- **Risk:** MEDIUM - MEV bots can back-run cap increases
- **Action Items:**
  - [ ] Test scenario: Owner increases cap, bot immediately fills new space
  - [ ] Analyze if fair distribution is compromised by MEV
  - [ ] Check if cap updates should have timelock/delay

#### 5.3 Sandwich Attacks
- **Location:** N/A - No AMM interactions
- **Risk:** MINIMAL - Not applicable
- **Action Items:**
  - [ ] Confirm no indirect sandwich vectors through CCA contract

#### 5.4 Transaction Ordering Dependence
- **Location:** First-come-first-served cap enforcement
- **Risk:** HIGH - Ordering determines who gets to bid
- **Action Items:**
  - [ ] Document ordering assumptions (is this intended behavior?)
  - [ ] Test scenario: Two bids compete for last 1 ETH of cap
  - [ ] Verify failed bids revert cleanly (no partial fills)
  - [ ] Analyze if validators can reorder transactions for profit

#### 5.5 Expiry Boundary Gaming
- **Location:** Permit expiry check (line 79)
- **Risk:** MEDIUM - Users can time bids to exploit expiry
- **Action Items:**
  - [ ] Test scenario: User delays bid until just before expiry
  - [ ] Check if short-lived permits enable gaming
  - [ ] Verify no incentive to hold permits until last second
  - [ ] Test: Can user get new permit if old one expired but still useful?

---

## 6. TOKEN HANDLING

**Relevance Score: 2/5** (Low Priority)

### Rationale
Contract does not custody tokens or ETH. However, it tracks token/ETH amounts passed by CCA contract. Mismatch between tracking and reality is a risk.

### Check Items

#### 6.1 Token Transfer Exploits
- **Location:** N/A - No token transfers in Permitter
- **Risk:** N/A
- **Action Items:**
  - [ ] Verify CCA contract handles actual transfers securely
  - [ ] Document trust boundary between Permitter and CCA

#### 6.2 Accounting Mismatch
- **Location:** `bidAmount` and `ethValue` parameters (line 68-69)
- **Risk:** HIGH - Contract trusts CCA to pass correct values
- **Action Items:**
  - [ ] Test scenario: CCA passes incorrect `bidAmount` (inflate tracked value)
  - [ ] Test scenario: CCA passes incorrect `ethValue` (bypass caps)
  - [ ] Verify no way to detect/prevent CCA lying about values
  - [ ] Document this trust assumption prominently
  - [ ] Check if `bidAmount` and `ethValue` should have relationship validation

#### 6.3 Fee-on-Transfer / Rebasing Tokens
- **Location:** N/A - Token type unknown
- **Risk:** LOW - Permitter doesn't handle transfers
- **Action Items:**
  - [ ] Document token compatibility assumptions
  - [ ] Verify CCA contract handles special token types

#### 6.4 ETH vs WETH Confusion
- **Location:** `ethValue` parameter vs `totalEthRaised` tracking
- **Risk:** LOW - Naming suggests ETH, but could be WETH
- **Action Items:**
  - [ ] Clarify if `ethValue` is wei of ETH or WETH tokens
  - [ ] Verify unit consistency (wei vs tokens)

---

## 7. DENIAL OF SERVICE

**Relevance Score: 4/5** (High Priority)

### Rationale
Owner can pause contract. Caps can be set to 0. Unbounded mapping growth. Multiple DoS vectors exist.

### Check Items

#### 7.1 Owner-Induced DoS
- **Location:** `pause()` function (line 142)
- **Risk:** HIGH - Owner can halt auction permanently
- **Action Items:**
  - [ ] Test scenario: Owner pauses during active auction
  - [ ] Verify no unpause deadline or forced unpause mechanism
  - [ ] Check if paused state can be used for griefing
  - [ ] Analyze: Should there be emergency unpause by governance?

#### 7.2 Cap-Induced DoS
- **Location:** `updateMaxTotalEth`, `updateMaxTokensPerBidder` (lines 120-131)
- **Risk:** HIGH - Owner can set caps to 0
- **Action Items:**
  - [ ] Test: Set `maxTotalEth = 0` (prevents all bids)
  - [ ] Test: Set `maxTokensPerBidder = 0` (prevents all bids)
  - [ ] Test: Set caps below `totalEthRaised` / cumulative bids (retroactive DoS)
  - [ ] Verify no minimum cap validation

#### 7.3 Gas Limit DoS
- **Location:** `validateBid()` computation (lines 72-116)
- **Risk:** LOW - Simple operations, unlikely to hit gas limit
- **Action Items:**
  - [ ] Measure worst-case gas consumption
  - [ ] Test with maximum-length `permitData`
  - [ ] Verify ECDSA recovery gas costs are bounded
  - [ ] Check if signature length can be exploited (DoS via gas)

#### 7.4 Block Gas Limit Griefing
- **Location:** N/A - No loops
- **Risk:** MINIMAL
- **Action Items:**
  - [ ] Confirm no unbounded loops in any function

#### 7.5 Storage Exhaustion
- **Location:** `cumulativeBids` mapping (line 28)
- **Risk:** LOW - Mappings auto-expand, but state grows forever
- **Action Items:**
  - [ ] Estimate state growth over time (1000s of bidders)
  - [ ] Verify no practical limit to unique bidders
  - [ ] Check if state bloat is acceptable for use case
  - [ ] Analyze: Should there be bidder limit or cleanup mechanism?

---

## 8. FLASH LOAN VECTORS

**Relevance Score: 1/5** (Minimal Priority)

### Rationale
No borrows, no liquidity provision, no price-based logic. Flash loan attacks not directly applicable. However, atomic transactions could enable complex exploits.

### Check Items

#### 8.1 Flash Loan Price Manipulation
- **Location:** N/A
- **Risk:** N/A - No price dependencies
- **Action Items:**
  - [ ] Confirm no indirect price manipulation vectors

#### 8.2 Flash Loan-Enabled Atomicity Exploits
- **Location:** Multiple bids in single transaction
- **Risk:** LOW - CCA contract controls bid submission
- **Action Items:**
  - [ ] Test scenario: User submits multiple bids atomically
  - [ ] Verify cumulative tracking works across multiple same-tx calls
  - [ ] Check if atomic bid sequences enable cap gaming
  - [ ] Analyze: Can user probe caps without committing (revert patterns)?

#### 8.3 Flash Loan-Funded Griefing
- **Location:** N/A - Contract doesn't hold funds
- **Risk:** MINIMAL
- **Action Items:**
  - [ ] Verify no griefing vectors requiring temporary capital

---

## 9. CREATE2 & ADDRESS ISSUES

**Relevance Score: 3/5** (Medium Priority)

### Rationale
Factory uses CREATE2 for deterministic deployment. Salt salting prevents front-running, but introduces complexity. Address prediction is critical for integrations.

### Check Items

#### 9.1 CREATE2 Address Collision
- **Location:** `PermitterFactory.sol::createPermitter()` (line 14)
- **Risk:** LOW - Collision would require hash collision
- **Action Items:**
  - [ ] Test: Deploy same parameters twice from same sender (should revert)
  - [ ] Verify CREATE2 protection prevents redeployment
  - [ ] Check if init code hash is calculated correctly (lines 44-48)
  - [ ] Test edge case: Different sender, same salt (different addresses)

#### 9.2 CREATE2 Front-Running
- **Location:** Salt salting mechanism (line 22)
- **Risk:** LOW - Mitigated by including `msg.sender` in salt
- **Action Items:**
  - [ ] Test scenario: Attacker sees pending factory call, tries to front-run
  - [ ] Verify `msg.sender` inclusion prevents address prediction by others
  - [ ] Check if contract-based deployer changes `msg.sender` (proxy calls)
  - [ ] Analyze: Can attacker grief by deploying to predicted addresses?

#### 9.3 Address Prediction Accuracy
- **Location:** `predictPermitterAddress()` function (lines 33-56)
- **Risk:** MEDIUM - Incorrect prediction breaks integrations
- **Action Items:**
  - [ ] Fuzz test: Compare predicted vs actual deployed addresses
  - [ ] Verify salt derivation matches between create and predict (lines 22 vs 41)
  - [ ] Test with all parameter combinations (zero values, max values)
  - [ ] Check if init code includes correct constructor parameters encoding

#### 9.4 Init Code Hash Drift
- **Location:** Line 48 - `keccak256(initCode)`
- **Risk:** MEDIUM - Compiler changes could alter init code
- **Action Items:**
  - [ ] Verify init code hash stability across Solidity versions
  - [ ] Document compiler version lock requirement
  - [ ] Test if optimizer settings affect init code hash
  - [ ] Check if `type(Permitter).creationCode` is deterministic

#### 9.5 Self-Destruct / CREATE2 Redeployment
- **Location:** Deployed Permitter contracts
- **Risk:** MINIMAL - Solidity 0.8.30 on Cancun (SELFDESTRUCT behavior changed)
- **Action Items:**
  - [ ] Verify Permitter has no SELFDESTRUCT opcode
  - [ ] Confirm Cancun EVM rules prevent CREATE2 address reuse
  - [ ] Document implications of SELFDESTRUCT deprecation

---

## 10. CROSS-CONTRACT INTERACTIONS

**Relevance Score: 4/5** (High Priority)

### Rationale
Permitter is designed to be called by Uniswap CCA contract (not in scope). Trust boundary and integration assumptions are critical.

### Check Items

#### 10.1 Caller Validation
- **Location:** `validateBid()` has no caller restrictions
- **Risk:** HIGH - Assumes only CCA contract calls
- **Action Items:**
  - [ ] Test: Can arbitrary contract call `validateBid`?
  - [ ] Test: Can EOA call `validateBid` directly?
  - [ ] Verify impact of malicious caller passing crafted parameters
  - [ ] Analyze: Should there be CCA contract whitelist?
  - [ ] Check if msg.sender validation is needed

#### 10.2 Return Value Handling
- **Location:** `validateBid()` returns `bool valid` (line 116)
- **Risk:** MEDIUM - CCA must check return value or catch reverts
- **Action Items:**
  - [ ] Verify function always returns `true` or reverts (never returns false)
  - [ ] Check if CCA contract properly handles reverts
  - [ ] Test: What happens if CCA ignores return value?
  - [ ] Analyze: Should function return `false` instead of reverting?

#### 10.3 State Synchronization
- **Location:** `totalEthRaised` and `cumulativeBids` tracking
- **Risk:** CRITICAL - Permitter state can desync from CCA
- **Action Items:**
  - [ ] Test scenario: CCA reverts bid after Permitter validates (state divergence)
  - [ ] Test scenario: CCA accepts bid after Permitter rejects (should not happen)
  - [ ] Verify no reentrancy allows CCA to manipulate state
  - [ ] Document: Who is source of truth for bid state?
  - [ ] Check if state can be reconciled if desync occurs

#### 10.4 Multi-Permitter Interference
- **Location:** Multiple Permitter instances from factory
- **Risk:** LOW - Each instance isolated
- **Action Items:**
  - [ ] Verify instances do not share state
  - [ ] Test scenario: Two auctions with same bidder address
  - [ ] Check if permits from one auction work in another (should not - EIP-712 domain)
  - [ ] Confirm factory contract has no shared state

#### 10.5 Upgrade Coordination
- **Location:** N/A - No upgrade mechanism
- **Risk:** MEDIUM - If CCA upgrades, Permitter becomes incompatible
- **Action Items:**
  - [ ] Document version compatibility requirements
  - [ ] Verify no way to migrate state to new Permitter
  - [ ] Check what happens if CCA changes validation interface

---

## 11. CRYPTOGRAPHIC ISSUES

**Relevance Score: 5/5** (Critical Priority)

### Rationale
EIP-712 signatures are the core security mechanism. Signature verification bugs = complete system compromise.

### Check Items

#### 11.1 Signature Malleability (ECDSA)
- **Location:** `ECDSA.recover()` usage (line 181)
- **Risk:** HIGH - OpenZeppelin ECDSA should handle, but verify
- **Action Items:**
  - [ ] Test: Can signature (r,s,v) be manipulated to produce different valid signature?
  - [ ] Verify OpenZeppelin ECDSA prevents (r, s) vs (r, -s mod n) malleability
  - [ ] Check `v` value validation (should be 27 or 28)
  - [ ] Test: Does contract accept both standard and compact signatures?
  - [ ] Review OpenZeppelin ECDSA version for known issues

#### 11.2 Signature Replay Attacks
- **Location:** Permit reuse (no nonce system)
- **Risk:** HIGH - Permits are reusable by design
- **Action Items:**
  - [ ] Document: Permits SHOULD be reusable (not a bug)
  - [ ] Test scenario: User gets permit, uses it, uses it again (should work until cap)
  - [ ] Test scenario: User gets 2 permits with different caps, uses both (griefing?)
  - [ ] Verify caps prevent infinite replay
  - [ ] Check if permit revocation is possible (currently not)

#### 11.3 Cross-Chain Replay Protection
- **Location:** EIP-712 domain separator (line 55)
- **Risk:** LOW - chainId in domain separator
- **Action Items:**
  - [ ] Verify `_domainSeparatorV4()` includes chainId
  - [ ] Test: Can permit from chain A work on chain B? (should not)
  - [ ] Check if factory deployed to same address on multiple chains
  - [ ] Analyze: What happens if chain forks?

#### 11.4 Cross-Contract Replay Protection
- **Location:** EIP-712 domain separator (line 55)
- **Risk:** LOW - verifyingContract in domain separator
- **Action Items:**
  - [ ] Verify domain separator includes contract address
  - [ ] Test: Can permit for Permitter A work in Permitter B? (should not)
  - [ ] Check if multiple Permitters for same auction creates confusion

#### 11.5 EIP-712 Domain Separator Correctness
- **Location:** Constructor `EIP712("Permitter", "1")` (line 55)
- **Risk:** MEDIUM - Hardcoded values
- **Action Items:**
  - [ ] Verify name="Permitter" is correct (matches documentation?)
  - [ ] Verify version="1" is appropriate (no versioning scheme)
  - [ ] Test: Calculate domain separator manually, compare to contract
  - [ ] Check: `domainSeparator()` function (line 165) returns correct value
  - [ ] Review OpenZeppelin EIP712 implementation for cache invalidation issues

#### 11.6 Permit Structure Hash
- **Location:** PERMIT_TYPEHASH (lines 15-16)
- **Risk:** MEDIUM - Must match off-chain signing
- **Action Items:**
  - [ ] Verify typehash matches: `keccak256("Permit(address bidder,uint256 maxBidAmount,uint256 expiry)")`
  - [ ] Check field order: bidder, maxBidAmount, expiry (line 179)
  - [ ] Test: Off-chain signature generation matches on-chain verification
  - [ ] Verify no extra fields or missing fields

#### 11.7 Zero Address Recovery
- **Location:** ECDSA.recover can return address(0) on invalid signatures
- **Risk:** HIGH - If trustedSigner == address(0), invalid signatures pass
- **Action Items:**
  - [ ] Test: Pass malformed signature, verify recovery returns address(0)
  - [ ] Test: Can trustedSigner be set to address(0)? (no - constructor checks)
  - [ ] Test: What if owner updates trustedSigner to address(0)? (checked at line 135)
  - [ ] Verify ECDSA.recover never returns address(0) for valid but unauthorized signatures

#### 11.8 Signature Length Validation
- **Location:** `signature` parameter (line 76)
- **Risk:** LOW - OpenZeppelin ECDSA validates
- **Action Items:**
  - [ ] Test: Pass signature of length 0 (should revert)
  - [ ] Test: Pass signature of length 64 (compact) vs 65 (standard)
  - [ ] Test: Pass oversized signature (should revert)
  - [ ] Verify OpenZeppelin ECDSA handles all cases

---

## 12. ECONOMIC & GAME THEORY

**Relevance Score: 4/5** (High Priority)

### Rationale
Auction mechanics create economic incentives. Cap manipulation, MEV extraction, and permit gaming are concerns.

### Check Items

#### 12.1 Incentive Misalignment
- **Location:** Owner can change caps mid-auction (lines 120-131)
- **Risk:** HIGH - Owner can favor certain bidders
- **Action Items:**
  - [ ] Test scenario: Owner increases cap when their preferred bidder needs space
  - [ ] Test scenario: Owner decreases cap to lock out latecomers
  - [ ] Analyze: Does owner have financial stake in auction outcome?
  - [ ] Check if cap changes can be front-run by insiders
  - [ ] Verify events provide transparency for cap changes

#### 12.2 MEV Extraction Vectors
- **Location:** Bid ordering and cap enforcement (lines 91-105)
- **Risk:** HIGH - Validators/bots can extract value
- **Action Items:**
  - [ ] Quantify MEV potential: How much value in front-running bids?
  - [ ] Test scenario: Bot monitors mempool, front-runs all bids
  - [ ] Analyze: Does private mempool (Flashbots) mitigate this?
  - [ ] Check if auction mechanism should include MEV mitigation
  - [ ] Document: Is MEV acceptable for this use case?

#### 12.3 Griefing Attacks (Economic)
- **Location:** Cap exhaustion without intent to participate
- **Risk:** MEDIUM - Attacker fills cap, preventing others
- **Action Items:**
  - [ ] Test scenario: Attacker gets permit, fills cap, then cancels bid in CCA
  - [ ] Verify: Can Permitter track bidder who filled cap but didn't pay?
  - [ ] Check if KYC requirements mitigate (attacker identity known)
  - [ ] Analyze: Cost of griefing attack vs benefit

#### 12.4 Permit Arbitrage
- **Location:** Multiple permits with different caps
- **Risk:** MEDIUM - User gets multiple permits, exploits best one
- **Action Items:**
  - [ ] Test scenario: User requests permit with cap 100, then cap 200, uses both
  - [ ] Verify: Cumulative tracking prevents over-allocation across permits
  - [ ] Check: Can user game signer to get multiple permits?
  - [ ] Analyze: Should permits include nonce to prevent this?

#### 12.5 Cap Gaming
- **Location:** `maxTokensPerBidder` vs `permit.maxBidAmount` (lines 98-100)
- **Risk:** MEDIUM - Two cap systems can be confusing
- **Action Items:**
  - [ ] Test: permit.maxBidAmount > maxTokensPerBidder (which takes precedence? Line 98)
  - [ ] Test: Owner lowers maxTokensPerBidder below existing permit caps
  - [ ] Verify: Lower cap always wins (line 98 check)
  - [ ] Analyze: Why two cap systems? (flexibility vs complexity)

#### 12.6 Sybil Attacks
- **Location:** KYC enforced off-chain, on-chain only checks signatures
- **Risk:** HIGH - If KYC compromised, user creates multiple identities
- **Action Items:**
  - [ ] Document: Permitter assumes KYC prevents Sybil attacks
  - [ ] Verify: No on-chain Sybil protection
  - [ ] Check: Total cap (`maxTotalEth`) is only defense
  - [ ] Analyze: Trust model assumes signer performs proper KYC

---

## 13. UPGRADE & GOVERNANCE RISKS

**Relevance Score: 2/5** (Low Priority)

### Rationale
No upgrade mechanisms. No proxies. Immutable code. However, parameter changes by owner are a form of "governance".

### Check Items

#### 13.1 Proxy Upgrade Vulnerabilities
- **Location:** N/A - No proxies
- **Risk:** N/A
- **Action Items:**
  - [ ] Confirm no delegatecall usage
  - [ ] Verify no proxy patterns

#### 13.2 Storage Layout Conflicts
- **Location:** N/A - No upgrades possible
- **Risk:** N/A
- **Action Items:**
  - [ ] Document: State is permanent, cannot be migrated

#### 13.3 Parameter Update Risks (Governance)
- **Location:** `updateMaxTotalEth`, `updateMaxTokensPerBidder`, `updateTrustedSigner`
- **Risk:** MEDIUM - Owner is de-facto governor
- **Action Items:**
  - [ ] Test scenario: Owner rapidly changes parameters (volatility)
  - [ ] Verify: No rate limiting on updates
  - [ ] Check: No validation on new parameter values (can be extreme)
  - [ ] Analyze: Should there be min/max bounds?
  - [ ] Document: Recommended governance practices (multisig, timelock)

#### 13.4 Emergency Stop Mechanism
- **Location:** `pause()` / `unpause()` (lines 142-151)
- **Risk:** MEDIUM - Owner-controlled, no checks
- **Action Items:**
  - [ ] Test: Pause during active auction
  - [ ] Verify: No automatic unpause timer
  - [ ] Check: Can pause be abused for griefing?
  - [ ] Analyze: Should there be guardian role (separate from owner)?
  - [ ] Document: When should pause be used?

#### 13.5 Immutable vs. Upgradeable Trade-offs
- **Location:** Entire system design
- **Risk:** LOW - Immutability is a security feature
- **Action Items:**
  - [ ] Document: No bug fixes possible after deployment
  - [ ] Verify: Factory can deploy new versions if needed
  - [ ] Check: Can state be migrated if critical bug found? (no)
  - [ ] Analyze: Risk of being locked into buggy version

---

## 14. INTEGRATION-SPECIFIC RISKS

**Relevance Score: 5/5** (Critical Priority)

### Rationale
Permitter is a hook/plugin for Uniswap CCA (external system not in scope). Integration assumptions are critical.

### Check Items

#### 14.1 CCA Contract Trust Assumptions
- **Location:** `validateBid()` parameters (lines 67-70)
- **Risk:** CRITICAL - Entire security model assumes CCA is honest
- **Action Items:**
  - [ ] Document EXPLICITLY: Permitter trusts CCA to pass correct values
  - [ ] List all trust assumptions:
    - [ ] CCA passes correct `bidder` address
    - [ ] CCA passes correct `bidAmount` (tokens)
    - [ ] CCA passes correct `ethValue` (ETH)
    - [ ] CCA only calls when bid is actually placed
    - [ ] CCA reverts if Permitter rejects bid
  - [ ] Verify: What happens if CCA is malicious/buggy?
  - [ ] Test: Permitter with mock malicious CCA

#### 14.2 CCA Integration Points
- **Location:** Return value and revert behavior
- **Risk:** HIGH - CCA must handle Permitter responses correctly
- **Action Items:**
  - [ ] Document: Expected CCA behavior on `validateBid` revert
  - [ ] Verify: CCA doesn't silently ignore reverts (catch-try patterns)
  - [ ] Check: CCA atomicity (bid succeeds only if validation passes)
  - [ ] Test: Integration with actual CCA contract (if available)

#### 14.3 Event Monitoring for CCA
- **Location:** `PermitVerified` event (lines 112-114)
- **Risk:** LOW - Informational only
- **Action Items:**
  - [ ] Verify: Events provide enough data for off-chain monitoring
  - [ ] Check: CCA or users rely on these events?
  - [ ] Test: Event data accuracy (remaining caps calculation)

#### 14.4 State Desynchronization
- **Location:** `totalEthRaised` vs actual ETH in CCA contract
- **Risk:** CRITICAL - Can diverge if CCA has bugs
- **Action Items:**
  - [ ] Test scenario: CCA accepts bid but doesn't transfer ETH
  - [ ] Test scenario: CCA transfers more/less ETH than `ethValue`
  - [ ] Verify: No reconciliation mechanism
  - [ ] Document: Permitter state is best-effort tracking, not source of truth

#### 14.5 Multi-Auction Scenarios
- **Location:** Factory deploys one Permitter per auction
- **Risk:** LOW - Isolated instances
- **Action Items:**
  - [ ] Verify: Each auction gets unique Permitter
  - [ ] Test: Same bidder participates in multiple auctions (separate caps)
  - [ ] Check: Permits for auction A don't work in auction B (EIP-712 protection)

---

## 15. EDGE CASES & BOUNDARY CONDITIONS

**Relevance Score: 4/5** (High Priority)

### Rationale
Edge cases often reveal vulnerabilities. Zero values, maximum values, and boundary conditions require thorough testing.

### Check Items

#### 15.1 Zero Values
- **Location:** Throughout contract
- **Risk:** MEDIUM - May cause unexpected behavior
- **Action Items:**
  - [ ] Test: `bidAmount = 0` (should be allowed?)
  - [ ] Test: `ethValue = 0` (should be allowed?)
  - [ ] Test: `permit.maxBidAmount = 0` (prevents bidding)
  - [ ] Test: `permit.expiry = 0` (always expired)
  - [ ] Test: `maxTotalEth = 0` (DoS)
  - [ ] Test: `maxTokensPerBidder = 0` (DoS)
  - [ ] Test: Deploy with all parameters = 0

#### 15.2 Maximum Values
- **Location:** Throughout contract
- **Risk:** MEDIUM - Overflow edge cases
- **Action Items:**
  - [ ] Test: `bidAmount = type(uint256).max`
  - [ ] Test: `ethValue = type(uint256).max`
  - [ ] Test: `permit.maxBidAmount = type(uint256).max`
  - [ ] Test: `permit.expiry = type(uint256).max`
  - [ ] Test: `maxTotalEth = type(uint256).max`
  - [ ] Test: `maxTokensPerBidder = type(uint256).max`
  - [ ] Test: `alreadyBid + bidAmount` when both large

#### 15.3 Expiry Boundary
- **Location:** Line 79 - `block.timestamp > permit.expiry`
- **Risk:** MEDIUM - Off-by-one errors
- **Action Items:**
  - [ ] Test: `permit.expiry = block.timestamp` (should fail - strictly greater)
  - [ ] Test: `permit.expiry = block.timestamp - 1` (should fail)
  - [ ] Test: `permit.expiry = block.timestamp + 1` (should pass)
  - [ ] Verify: Expiry semantics match documentation

#### 15.4 Cap Boundaries
- **Location:** Lines 93-105 (cap checks)
- **Risk:** HIGH - Off-by-one allows bypass
- **Action Items:**
  - [ ] Test: `newCumulative = permit.maxBidAmount` (should fail - strictly greater)
  - [ ] Test: `newCumulative = permit.maxBidAmount - 1` (should pass)
  - [ ] Test: `newCumulative = permit.maxBidAmount + 1` (should fail)
  - [ ] Same tests for `maxTokensPerBidder` (line 98)
  - [ ] Same tests for `maxTotalEth` (line 105)

#### 15.5 Address Edge Cases
- **Location:** `bidder`, `trustedSigner`, `owner` addresses
- **Risk:** LOW - Mostly validated
- **Action Items:**
  - [ ] Test: `bidder = address(0)` (allowed?)
  - [ ] Test: `trustedSigner = address(0)` (prevented at construction & update)
  - [ ] Test: `owner = address(0)` (prevented at construction)
  - [ ] Test: All three addresses the same (weird but allowed?)

#### 15.6 Signature Edge Cases
- **Location:** `permitData` and signature parsing
- **Risk:** MEDIUM - Malformed data
- **Action Items:**
  - [ ] Test: `permitData` length = 0 (should revert on decode)
  - [ ] Test: Malformed `permitData` (invalid ABI encoding)
  - [ ] Test: `signature` length != 65 (OpenZeppelin handles)
  - [ ] Test: All-zero signature
  - [ ] Test: Signature with invalid `v` value (not 27/28)

---

## 16. ADDITIONAL ISSUE CATEGORIES

### 16.1 Business Logic Vulnerabilities

**Relevance Score: 4/5** (High Priority)

- **Location:** Core validation logic
- **Risk:** HIGH - Logic errors bypass security
- **Action Items:**
  - [ ] Verify: Cumulative bid tracking is correct for intended use
  - [ ] Test: Can user bid, get refund in CCA, bid again (double-count?)
  - [ ] Check: Two-cap system (global + per-permit) works correctly
  - [ ] Analyze: Permit lifetime vs auction duration assumptions
  - [ ] Validate: State persistence after auction ends is acceptable

### 16.2 Error Handling

**Relevance Score: 3/5** (Medium Priority)

- **Location:** Custom errors throughout
- **Risk:** LOW - Errors are descriptive
- **Action Items:**
  - [ ] Verify: All error cases have custom errors
  - [ ] Test: Error messages provide useful debugging info
  - [ ] Check: No silent failures or returns false instead of revert
  - [ ] Analyze: Event emissions on errors (none currently)

### 16.3 Event Integrity

**Relevance Score: 2/5** (Low Priority)

- **Location:** Event emissions (lines 112-114, 123, 130, 138, 144, 150)
- **Risk:** LOW - Events are informational
- **Action Items:**
  - [ ] Verify: All state changes emit events
  - [ ] Test: Event data accuracy (calculations in line 113)
  - [ ] Check: Indexed fields are appropriate
  - [ ] Analyze: Off-chain systems depend on events?

### 16.4 Gas Optimization Attacks

**Relevance Score: 2/5** (Low Priority)

- **Location:** High-optimization setting (10M runs)
- **Risk:** LOW - May introduce edge case bugs
- **Action Items:**
  - [ ] Test: Contract behaves identically with lower optimization
  - [ ] Verify: No optimizer bugs in Solidity 0.8.30
  - [ ] Check: Gas costs are predictable
  - [ ] Analyze: Does optimization affect security?

### 16.5 Compiler & Tooling Risks

**Relevance Score: 2/5** (Low Priority)

- **Location:** Solidity 0.8.30, Cancun EVM
- **Risk:** LOW - Mature compiler version
- **Action Items:**
  - [ ] Verify: No known Solidity 0.8.30 bugs affecting this code
  - [ ] Check: Cancun EVM features used correctly (if any)
  - [ ] Test: Deployment on Cancun-compatible networks
  - [ ] Review: OpenZeppelin library version compatibility

---

## SUMMARY OF CRITICAL AREAS

Based on reconnaissance findings, the following areas require **CRITICAL** focus during deep-dive analysis:

### Top 5 Critical Risks

1. **Cryptographic Security (Category 11)**
   - EIP-712 signature verification correctness
   - Signature malleability and replay protection
   - Zero-address recovery edge cases

2. **CCA Integration Trust Boundary (Category 14)**
   - Parameter validation (trusting CCA for `bidAmount`, `ethValue`)
   - State synchronization and desync scenarios
   - Return value and revert handling

3. **Access Control & Owner Privileges (Category 2)**
   - Owner can DoS auction (pause, set caps to 0)
   - No ownership transfer mechanism
   - Trusted signer key compromise scenarios

4. **Economic & MEV Exploits (Category 12)**
   - Front-running bid submission
   - Cap manipulation for insider advantage
   - Permit arbitrage and gaming

5. **Cross-Contract Interactions (Category 10)**
   - Lack of caller validation on `validateBid`
   - State divergence from CCA contract
   - Multi-Permitter coordination

---

## NEXT STEPS

**Phase 3: Deep Dive Analysis**
- Systematically work through each category checklist
- Perform manual code review with checklist items in mind
- Write proof-of-concept exploits for identified vulnerabilities
- Fuzz test edge cases and boundary conditions
- Integration test with mock CCA contract

**Phase 4: Reporting**
- Document all findings with severity ratings
- Provide exploit code and mitigation recommendations
- Create summary report with risk assessment

---

**End of Phase 2: Issue Taxonomy**
