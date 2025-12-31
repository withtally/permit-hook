# Phase 1: Reconnaissance Report
**Permitter Smart Contract System**

**Audit Date:** 2025-12-31
**Auditor:** Security Review Team
**Codebase:** `/Users/rafael/conductor/workspaces/permit-hook/boise/src/`

---

## 1. CONTRACT INVENTORY

### 1.1 Core Contracts

#### **Permitter.sol** (183 lines)
- **Location:** `/Users/rafael/conductor/workspaces/permit-hook/boise/src/Permitter.sol`
- **Purpose:** Validation hook for Uniswap CCA (Continuous Combinatorial Auction) that enforces KYC-based permissions and caps using EIP-712 signed permits
- **Inheritance Chain:**
  - `IPermitter` (interface)
  - `EIP712` (OpenZeppelin - cryptographic domain separator)
- **State Variables:**
  - `trustedSigner` (address) - Authorized permit signer
  - `maxTotalEth` (uint256) - Global ETH raise cap
  - `maxTokensPerBidder` (uint256) - Per-bidder token cap
  - `cumulativeBids` (mapping) - Tracks cumulative bids per address
  - `totalEthRaised` (uint256) - Running total of ETH raised
  - `owner` (address) - Admin/governance address
  - `paused` (bool) - Emergency pause flag

#### **PermitterFactory.sol** (57 lines)
- **Location:** `/Users/rafael/conductor/workspaces/permit-hook/boise/src/PermitterFactory.sol`
- **Purpose:** Factory contract for deploying isolated Permitter instances using CREATE2 for deterministic addresses
- **Inheritance Chain:**
  - `IPermitterFactory` (interface)
- **No State Variables:** Stateless factory pattern
- **Deployment Pattern:** CREATE2 with salt salting (includes `msg.sender` in final salt)

### 1.2 Interfaces

#### **IPermitter.sol** (150 lines)
- **Location:** `/Users/rafael/conductor/workspaces/permit-hook/boise/src/interfaces/IPermitter.sol`
- **Defines:** Events, errors, structs, and function signatures for Permitter
- **Key Struct:**
  ```solidity
  struct Permit {
    address bidder;
    uint256 maxBidAmount;
    uint256 expiry;
  }
  ```

#### **IPermitterFactory.sol** (51 lines)
- **Location:** `/Users/rafael/conductor/workspaces/permit-hook/boise/src/interfaces/IPermitterFactory.sol`
- **Defines:** Factory deployment interface

### 1.3 External Dependencies

#### OpenZeppelin Contracts
- **Version:** Not explicitly pinned in contracts (using git submodule)
- **Location:** `lib/openzeppelin-contracts/`
- **Imports:**
  - `@openzeppelin/contracts/utils/cryptography/ECDSA.sol` - Signature recovery
  - `@openzeppelin/contracts/utils/cryptography/EIP712.sol` - Domain separator generation

#### Forge Standard Library
- **Location:** `lib/forge-std/`
- **Usage:** Testing only (not in production contracts)

### 1.4 Compiler Configuration

```toml
solc_version = "0.8.30"
evm_version = "cancun"
optimizer = true
optimizer_runs = 10_000_000
```

**Pragma:** All contracts use `pragma solidity 0.8.30;` (exact version lock)

**Notes:**
- High optimization setting (10M runs) indicates gas efficiency priority
- Cancun EVM version enables latest features (transient storage, blob transactions)
- No floating pragma issues - all locked to 0.8.30

---

## 2. ENTRY POINTS

### 2.1 External/Public Functions - Permitter.sol

#### State-Changing Functions

**`validateBid(address bidder, uint256 bidAmount, uint256 ethValue, bytes calldata permitData)`**
- **Visibility:** External
- **Access Control:** None (called by Uniswap CCA contract)
- **State Changes:** Updates `cumulativeBids[bidder]` and `totalEthRaised`
- **Critical Path:** Core validation logic
- **Returns:** `bool valid` (always true or reverts)
- **Risk Level:** HIGH - Main attack surface

**`updateMaxTotalEth(uint256 newMaxTotalEth)`**
- **Visibility:** External
- **Access Control:** `onlyOwner` modifier
- **State Changes:** Updates `maxTotalEth`
- **No validation on new value** (can be set to 0 or type(uint256).max)

**`updateMaxTokensPerBidder(uint256 newMaxTokensPerBidder)`**
- **Visibility:** External
- **Access Control:** `onlyOwner` modifier
- **State Changes:** Updates `maxTokensPerBidder`
- **No validation on new value**

**`updateTrustedSigner(address newSigner)`**
- **Visibility:** External
- **Access Control:** `onlyOwner` modifier
- **State Changes:** Updates `trustedSigner`
- **Validation:** Checks `newSigner != address(0)`

**`pause()`**
- **Visibility:** External
- **Access Control:** `onlyOwner` modifier
- **State Changes:** Sets `paused = true`

**`unpause()`**
- **Visibility:** External
- **Access Control:** `onlyOwner` modifier
- **State Changes:** Sets `paused = false`

#### View Functions

**`getBidAmount(address bidder)`**
- Returns cumulative bids for an address
- No access control

**`getTotalEthRaised()`**
- Returns total ETH raised
- No access control

**`domainSeparator()`**
- Returns EIP-712 domain separator
- No access control

**Public State Variables (auto-generated getters):**
- `trustedSigner()`
- `maxTotalEth()`
- `maxTokensPerBidder()`
- `cumulativeBids(address)`
- `totalEthRaised()`
- `owner()`
- `paused()`

### 2.2 External/Public Functions - PermitterFactory.sol

**`createPermitter(address trustedSigner, uint256 maxTotalEth, uint256 maxTokensPerBidder, address owner, bytes32 salt)`**
- **Visibility:** External
- **Access Control:** None (permissionless factory)
- **State Changes:** Deploys new contract
- **Risk Level:** MEDIUM - Front-running considerations (salt salting mitigates)

**`predictPermitterAddress(address trustedSigner, uint256 maxTotalEth, uint256 maxTokensPerBidder, address owner, bytes32 salt)`**
- **Visibility:** External (view)
- **Access Control:** None
- **Returns:** Predicted CREATE2 address

### 2.3 Payable Functions

**NONE** - No functions accept ETH. Contracts are not designed to hold ETH.

### 2.4 Callback Receivers

**NONE** - No ERC721/ERC1155/ERC777 hooks implemented.

### 2.5 Constructor Entry Points

**Permitter Constructor:**
```solidity
constructor(
  address _trustedSigner,
  uint256 _maxTotalEth,
  uint256 _maxTokensPerBidder,
  address _owner
) EIP712("Permitter", "1")
```
- Validates `_trustedSigner != address(0)`
- Validates `_owner != address(0)`
- Initializes EIP712 with name="Permitter", version="1"

**PermitterFactory Constructor:**
- None (no constructor defined)

---

## 3. ASSET FLOWS

### 3.1 Token Inflows

**NONE DIRECTLY**
- Contracts do not handle tokens or ETH directly
- Acts as a validation layer only
- Uniswap CCA contract handles actual asset transfers

### 3.2 Token Outflows

**NONE**
- No withdrawal functions
- No token transfer capabilities
- No ETH handling

### 3.3 Asset Flow Control

**N/A** - This is a validation hook system, not an asset custodian.

**Critical Observation:**
The Permitter contract tracks `totalEthRaised` and `bidAmount` but NEVER actually handles ETH. This is passed as a parameter by the calling CCA contract. **Potential mismatch risk if CCA contract passes incorrect values.**

---

## 4. PRIVILEGED ROLES

### 4.1 Owner Role (Permitter.sol)

**Powers:**
- Update `maxTotalEth` (can increase or decrease, even to 0)
- Update `maxTokensPerBidder` (can increase or decrease, even to 0)
- Update `trustedSigner` (can rotate signing key)
- Pause/unpause contract (emergency stop)

**Restrictions:**
- Cannot bypass signature verification
- Cannot modify cumulative bid tracking
- Cannot withdraw assets (none held)

**Access Control Pattern:**
```solidity
modifier onlyOwner() {
  if (msg.sender != owner) revert Unauthorized();
  _;
}
```

**Concerns:**
- **No ownership transfer function** - Owner is immutable once set in constructor
- **No timelock or multisig enforcement** - Single address control
- **No validation on cap updates** - Owner can set caps to extreme values

### 4.2 Trusted Signer Role

**Powers:**
- Issue permits that authorize bids
- Control who can participate in auction
- Set per-user caps via `maxBidAmount` in permit

**Restrictions:**
- Cannot modify contract state directly
- Subject to permit expiry times
- Signatures become invalid if rotated by owner

**Trust Assumptions:**
- Signer only issues permits to KYC-approved users
- Signer protects private key from compromise
- Signer issues fair and accurate `maxBidAmount` values

### 4.3 Upgrade Mechanisms

**NONE**
- Contracts are non-upgradeable
- No proxy patterns
- No delegatecall usage
- Immutable code once deployed

### 4.4 Multisig Requirements

**NONE ENFORCED**
- Owner is a single address
- Recommendation: Use multisig or governance contract as owner in production

---

## 5. EXTERNAL CALLS

### 5.1 External Contract Interactions

**OpenZeppelin ECDSA.recover()** (Permitter.sol:181)
```solidity
return ECDSA.recover(digest, signature);
```
- Library call (not external contract call)
- Used for signature verification
- Well-audited OpenZeppelin code

**None from PermitterFactory** - Only internal CREATE2 deployment

### 5.2 Oracle Dependencies

**NONE**
- No price feeds
- No off-chain data oracles
- All data comes from on-chain signatures

### 5.3 DEX Integrations

**NONE**
- Does not interact with DEXes
- Uniswap CCA is the caller, not callee

### 5.4 Callback Patterns

**NONE**
- No reentrancy vectors from external calls
- No callback functions to external contracts

---

## 6. INITIAL ATTACK SURFACE NOTES

### 6.1 Critical Security Observations

#### HIGH RISK AREAS

**1. Signature Validation Logic (validateBid)**
```solidity
// Line 84-85
address recovered = _recoverSigner(permit, signature);
if (recovered != trustedSigner) revert InvalidSignature(trustedSigner, recovered);
```
- **Concern:** What happens if ECDSA.recover() returns address(0) on malformed signatures?
- **Concern:** Is there protection against signature malleability?
- **Follow-up required:** Review OpenZeppelin ECDSA implementation version

**2. Cumulative Bid Tracking**
```solidity
// Line 91-95
uint256 alreadyBid = cumulativeBids[bidder];
uint256 newCumulative = alreadyBid + bidAmount;
if (newCumulative > permit.maxBidAmount) {
  revert ExceedsPersonalCap(bidAmount, permit.maxBidAmount, alreadyBid);
}
```
- **Concern:** No mechanism to reset `cumulativeBids` if auction fails/restarts
- **Concern:** Bidder can obtain multiple permits with different `maxBidAmount` values and replay old ones
- **Concern:** State persists forever, no cleanup mechanism

**3. Permit Replay Attacks**
```solidity
// No nonce tracking!
```
- **CRITICAL:** Permits do not include nonces
- **Risk:** Same permit can be reused across multiple bids until expiry or cap is reached
- **Mitigation:** This appears intentional (permits are meant to be reusable until caps hit)
- **But:** User could get multiple permits with different caps and choose which to use

**4. Parameter Trust in validateBid()**
```solidity
function validateBid(
  address bidder,
  uint256 bidAmount,
  uint256 ethValue,  // Passed by CCA contract - TRUSTED INPUT
  bytes calldata permitData
) external returns (bool valid)
```
- **CRITICAL:** Contract trusts that `bidAmount` and `ethValue` are correct
- **Risk:** If Uniswap CCA contract has bugs or is malicious, it could pass incorrect values
- **Risk:** Contract has no way to verify actual ETH was transferred

**5. Owner Privilege Escalation**
```solidity
// Lines 120-131
function updateMaxTotalEth(uint256 newMaxTotalEth) external onlyOwner {
  maxTotalEth = newMaxTotalEth;
}
```
- **Risk:** Owner can increase caps mid-auction to allow more bids
- **Risk:** Owner can decrease caps to 0 to DoS the auction
- **No events required before action** (though events are emitted)
- **No timelock delays**

#### MEDIUM RISK AREAS

**6. CREATE2 Salt Salting**
```solidity
// PermitterFactory.sol:22
bytes32 finalSalt = keccak256(abi.encodePacked(msg.sender, salt));
```
- **Good:** Prevents front-running by including msg.sender
- **Concern:** Different msg.sender cannot predict each other's addresses
- **Concern:** If factory is called via another contract, msg.sender might not be the auction creator

**7. Integer Overflow Protection**
```solidity
// Line 92, 104
uint256 newCumulative = alreadyBid + bidAmount;
uint256 newTotalEth = alreadyRaised + ethValue;
```
- **Good:** Solidity 0.8.30 has built-in overflow protection
- **But:** No explicit checks for reasonable bounds
- **Risk:** Extremely large values could cause unexpected behavior

**8. EIP-712 Domain Separator**
```solidity
// Constructor
EIP712("Permitter", "1")
```
- **Good:** Includes chainId and verifyingContract in domain separator
- **Good:** Prevents cross-chain and cross-contract replay
- **Concern:** Version is hardcoded as "1" - no upgrade path

**9. Pause Mechanism**
```solidity
// Line 73
if (paused) revert ContractPaused();
```
- **Good:** Fail-fast check at beginning of validateBid
- **Concern:** No unpause deadline - could be paused forever
- **Concern:** No emergency withdrawal mechanism (though none needed as no assets held)

#### LOW RISK AREAS

**10. Gas Optimization Patterns**
```solidity
// Lines 72-110: Ordered from cheap to expensive checks
// 1. CHEAPEST: Check if paused
// 2. Decode permit data
// 3. CHEAP: Check time window
// 4. MODERATE: Verify EIP-712 signature
// 5-6. Check caps
// 7-8. STORAGE operations
```
- **Good:** Efficient ordering minimizes wasted gas on reverts
- **Low Risk:** No security implications

### 6.2 First Impressions Summary

**Architecture:**
- Clean, minimal design
- Well-commented code
- Clear separation of concerns (factory vs hook)

**Code Quality:**
- Professional Solidity style
- Appropriate use of custom errors (gas efficient)
- Good event emissions

**Red Flags:**
1. **No permit nonce tracking** - Permits are reusable (may be intentional)
2. **Trusted external input** - Relies on CCA contract for accurate `bidAmount`/`ethValue`
3. **Immutable owner** - No transfer function, stuck with initial owner
4. **No cap update validation** - Owner can set extreme values
5. **No bid reset mechanism** - Cumulative bids persist forever

**Green Flags:**
1. Uses well-audited OpenZeppelin contracts
2. No complex DeFi interactions
3. No asset custody (low risk)
4. Clean access control patterns
5. Strong EIP-712 replay protection

### 6.3 Areas Requiring Deeper Review

**CRITICAL PRIORITY:**
1. **Signature malleability testing** - Can ECDSA.recover be gamed?
2. **Permit reuse scenarios** - What attacks are possible with reusable permits?
3. **Integration with Uniswap CCA** - What are the trust assumptions?
4. **Owner privilege abuse** - What's the worst owner can do?

**HIGH PRIORITY:**
5. **State persistence implications** - What happens after auction ends?
6. **Multiple permit issuance** - Can users get conflicting permits?
7. **Expiry boundary conditions** - `block.timestamp > expiry` (strictly greater)
8. **Factory front-running** - Is salt salting sufficient?

**MEDIUM PRIORITY:**
9. **Event log analysis** - Are all state changes properly logged?
10. **Gas griefing** - Can attacker cause excessive gas consumption?
11. **CREATE2 address prediction** - Correct implementation?
12. **Pause state management** - What happens to in-flight bids?

---

## 7. THREAT MODEL CONSIDERATIONS

### 7.1 Threat Actors

**Malicious Bidder:**
- Goal: Bid more than allowed cap
- Goal: Participate without KYC
- Goal: Reuse expired permits
- Goal: Use someone else's permit

**Malicious Owner:**
- Goal: Manipulate auction by changing caps
- Goal: DoS auction by pausing
- Goal: Rotate signer to invalidate existing permits

**Compromised Signer:**
- Goal: Issue permits to non-KYC users
- Goal: Issue permits with inflated caps
- Goal: Issue long-lived permits (expiry far in future)

**Malicious CCA Contract:**
- Goal: Pass incorrect `bidAmount`/`ethValue` to bypass caps
- Goal: Call validateBid with false parameters

**Front-runner:**
- Goal: Deploy factory with same salt before legitimate user
- Goal: Predict addresses for griefing attacks

### 7.2 Attack Vectors to Explore

1. **Signature Forgery/Manipulation**
2. **Permit Replay Across Different Bids**
3. **Cap Manipulation by Owner**
4. **Integer Overflow/Underflow** (unlikely in 0.8.30 but test edge cases)
5. **CREATE2 Collision Attacks**
6. **Griefing via Pausing**
7. **Storage Exhaustion** (unbounded mapping growth)
8. **EIP-712 Domain Confusion**

---

## 8. DEPENDENCIES & EXTERNAL FACTORS

### 8.1 Uniswap CCA Contract

**CRITICAL UNKNOWN:**
- Contract is not included in this repository
- Permitter assumes CCA will:
  - Pass correct `bidder` address
  - Pass correct `bidAmount` (tokens)
  - Pass correct `ethValue` (ETH)
  - Only call `validateBid()` when actual bid is placed
  - Handle actual token/ETH transfers

**Recommendation:** Obtain and review Uniswap CCA contract specification/code.

### 8.2 Off-Chain Infrastructure

**Trusted Signer (Tally Server):**
- Responsible for KYC verification
- Issues EIP-712 signatures
- Private key security is paramount
- No on-chain validation of KYC status

**Sumsub KYC:**
- Third-party KYC provider
- Webhook integration (off-chain)
- Trust assumption: KYC is legitimate

---

## 9. RECOMMENDATIONS FOR PHASE 2

### 9.1 Testing Focus Areas

1. **Fuzz testing signature verification** with malformed inputs
2. **Invariant testing** for cumulative bid tracking
3. **Integration testing** with mock CCA contract
4. **CREATE2 address prediction** verification
5. **Reentrancy testing** (though no external calls)
6. **Access control bypass attempts**
7. **Edge cases:** max uint256 values, address(0), etc.

### 9.2 Code Review Focus

1. **Line-by-line review** of `validateBid()` function
2. **OpenZeppelin version check** and known vulnerabilities
3. **EIP-712 implementation** correctness
4. **ECDSA signature recovery** edge cases
5. **Modifier security** (onlyOwner)

### 9.3 Documentation Requests

1. **Uniswap CCA integration specification**
2. **Permit lifecycle documentation**
3. **Expected auction flow and state transitions**
4. **Owner/governance model in production**
5. **Incident response plan** for compromised signer

---

## 10. SCOPE SUMMARY

**Total Contracts:** 2 main contracts + 2 interfaces
**Total Lines of Code:** ~290 SLOC (excluding interfaces and comments)
**External Dependencies:** OpenZeppelin (ECDSA, EIP712)
**Complexity:** Low-Medium
**Risk Level:** Medium-High (due to financial impact, KYC requirements)

**Audit Recommendation:** Proceed to Phase 2 (Deep Dive) with focus on signature validation, permit lifecycle, and owner privilege analysis.

---

**End of Phase 1 Reconnaissance Report**
