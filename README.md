# Permitter

A smart contract system for enforcing KYC-based permissions and caps on Uniswap CCA (Continuous Combinatorial Auction) token sales. Uses EIP-712 signed permits issued by an off-chain server after KYC verification, validated on-chain during each bid.

## Overview

Permitter acts as a validation hook for Uniswap CCA auctions, ensuring:
- Only KYC-verified users can participate
- Per-bidder token caps are enforced
- Total ETH raise caps are enforced
- Permits can be rotated if signing keys are compromised

## Architecture

```
Bidder (Wallet)
    │
    ├─── Complete KYC ──────────► Sumsub KYC
    │                                  │
    │                                  │ Webhook: KYC approved
    │                                  ▼
    ├─── Request permit ────────► Tally Server
    │                                  │
    │◄── EIP-712 signature ────────────┘
    │
    └─── Submit bid with signature ───► Uniswap CCA ──► Permitter
                                                          │
                                        Validation passes/fails
```

## Contracts

### PermitterFactory

Deploys isolated Permitter instances for each auction using CREATE2 for deterministic addresses.

```solidity
function createPermitter(
    address trustedSigner,
    uint256 maxTotalEth,
    uint256 maxTokensPerBidder,
    address owner,
    bytes32 salt
) external returns (address permitter);
```

### Permitter

Implements bid validation using EIP-712 signed permits.

**Permit Structure:**
```solidity
struct Permit {
    address bidder;       // Address authorized to bid
    uint256 maxBidAmount; // Maximum tokens this bidder can purchase (cumulative)
    uint256 expiry;       // Timestamp when permit expires
}
```

**Key Functions:**
- `validateBid()` - Called by CCA to validate bids
- `updateMaxTotalEth()` - Update total ETH cap (owner only)
- `updateMaxTokensPerBidder()` - Update per-bidder cap (owner only)
- `updateTrustedSigner()` - Rotate signing key (owner only)
- `pause()` / `unpause()` - Emergency controls (owner only)

## Usage

### Deploying a Permitter

```solidity
PermitterFactory factory = PermitterFactory(FACTORY_ADDRESS);
address permitter = factory.createPermitter(
    signerAddress,           // Trusted signer (backend)
    100 ether,               // Max total ETH
    1000 * 10**18,           // Max tokens per bidder
    ownerAddress,            // Contract owner
    keccak256("my-auction")  // Salt for deterministic address
);
```

### Issuing Permits (Off-chain)

```typescript
const domain = {
    name: 'Permitter',
    version: '1',
    chainId: 1,
    verifyingContract: permitterAddress
};

const types = {
    Permit: [
        { name: 'bidder', type: 'address' },
        { name: 'maxBidAmount', type: 'uint256' },
        { name: 'expiry', type: 'uint256' }
    ]
};

const permit = {
    bidder: userAddress,
    maxBidAmount: parseEther('1000'),
    expiry: Math.floor(Date.now() / 1000) + 86400 // 24 hours
};

const signature = await signer._signTypedData(domain, types, permit);
```

### Placing a Bid

```typescript
const permitData = ethers.utils.defaultAbiCoder.encode(
    ['tuple(address,uint256,uint256)', 'bytes'],
    [[permit.bidder, permit.maxBidAmount, permit.expiry], signature]
);

await ccaContract.placeBid(bidAmount, permitData);
```

## Development

Built with [Foundry](https://github.com/foundry-rs/foundry).

### Build

```bash
forge build
```

### Test

```bash
forge test
```

### Format

```bash
forge fmt
```

## Security

### Trust Model
- **Trusted Signer**: Issues permits only to KYC-approved users
- **Owner**: Can pause, update caps, rotate signer (cannot bypass signature verification)
- **Cryptographic Enforcement**: EIP-712 signatures prevent forgery

### Replay Protection
- Domain separator includes `chainId` (prevents cross-chain replay)
- Domain separator includes `verifyingContract` (prevents cross-auction replay)

### Key Rotation
If the signing key is compromised:
1. Owner calls `updateTrustedSigner(newAddress)`
2. All old signatures become invalid immediately
3. Users must request new permits

## Disclaimer

**This code has not been audited.** Use at your own risk. A comprehensive security audit is recommended before any production deployment.

## License

MIT
