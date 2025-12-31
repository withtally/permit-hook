// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {IPermitter} from "./interfaces/IPermitter.sol";

/// @title Permitter
/// @notice Implements Uniswap CCA ValidationHook interface for bid validation using EIP-712 signed
/// permits. Enforces KYC-based permissions and caps on token sales.
/// @dev Uses EIP-712 signatures for gasless permit verification. The domain separator includes
/// chainId and verifyingContract to prevent cross-chain and cross-auction replay attacks.
contract Permitter is IPermitter, EIP712 {
  /// @notice EIP-712 typehash for the Permit struct.
  bytes32 public constant PERMIT_TYPEHASH =
    keccak256("Permit(address bidder,uint256 maxBidAmount,uint256 expiry)");

  /// @notice Address authorized to sign permits.
  address public trustedSigner;

  /// @notice Maximum total ETH that can be raised.
  uint256 public maxTotalEth;

  /// @notice Maximum tokens any single bidder can purchase.
  uint256 public maxTokensPerBidder;

  /// @notice Cumulative bid amounts per address.
  mapping(address bidder => uint256 amount) public cumulativeBids;

  /// @notice Total ETH raised across all bidders.
  uint256 public totalEthRaised;

  /// @notice Owner address that can update caps and pause.
  address public owner;

  /// @notice Whether the contract is paused.
  bool public paused;

  /// @notice Modifier to restrict access to owner only.
  modifier onlyOwner() {
    if (msg.sender != owner) revert Unauthorized();
    _;
  }

  /// @notice Creates a new Permitter instance.
  /// @param _trustedSigner Address authorized to sign permits.
  /// @param _maxTotalEth Maximum total ETH that can be raised.
  /// @param _maxTokensPerBidder Maximum tokens any single bidder can purchase.
  /// @param _owner Address that can update caps and pause.
  constructor(address _trustedSigner, uint256 _maxTotalEth, uint256 _maxTokensPerBidder, address _owner)
    EIP712("Permitter", "1")
  {
    if (_trustedSigner == address(0)) revert InvalidTrustedSigner();
    if (_owner == address(0)) revert InvalidOwner();

    trustedSigner = _trustedSigner;
    maxTotalEth = _maxTotalEth;
    maxTokensPerBidder = _maxTokensPerBidder;
    owner = _owner;
  }

  /// @inheritdoc IPermitter
  function validateBid(
    address bidder,
    uint256 bidAmount,
    uint256 ethValue,
    bytes calldata permitData
  ) external returns (bool valid) {
    // 1. CHEAPEST: Check if paused
    if (paused) revert ContractPaused();

    // 2. Decode permit data
    (Permit memory permit, bytes memory signature) = abi.decode(permitData, (Permit, bytes));

    // 3. CHEAP: Check time window
    if (block.timestamp > permit.expiry) {
      revert SignatureExpired(permit.expiry, block.timestamp);
    }

    // 4. MODERATE: Verify EIP-712 signature
    address recovered = _recoverSigner(permit, signature);
    if (recovered != trustedSigner) {
      revert InvalidSignature(trustedSigner, recovered);
    }

    // 5. Check permit is for this bidder
    if (permit.bidder != bidder) {
      revert InvalidSignature(bidder, permit.bidder);
    }

    // 6. STORAGE READ: Check individual cap
    uint256 alreadyBid = cumulativeBids[bidder];
    uint256 newCumulative = alreadyBid + bidAmount;
    if (newCumulative > permit.maxBidAmount) {
      revert ExceedsPersonalCap(bidAmount, permit.maxBidAmount, alreadyBid);
    }

    // Also check against global maxTokensPerBidder if it's lower
    if (newCumulative > maxTokensPerBidder) {
      revert ExceedsPersonalCap(bidAmount, maxTokensPerBidder, alreadyBid);
    }

    // 7. STORAGE READ: Check global cap
    uint256 alreadyRaised = totalEthRaised;
    uint256 newTotalEth = alreadyRaised + ethValue;
    if (newTotalEth > maxTotalEth) {
      revert ExceedsTotalCap(ethValue, maxTotalEth, alreadyRaised);
    }

    // 8. STORAGE WRITE: Update state
    cumulativeBids[bidder] = newCumulative;
    totalEthRaised = newTotalEth;

    // 9. Emit event for monitoring
    emit PermitVerified(
      bidder, bidAmount, permit.maxBidAmount - newCumulative, maxTotalEth - newTotalEth
    );

    return true;
  }

  /// @inheritdoc IPermitter
  function updateMaxTotalEth(uint256 newMaxTotalEth) external onlyOwner {
    uint256 oldCap = maxTotalEth;
    maxTotalEth = newMaxTotalEth;
    emit CapUpdated(CapType.TOTAL_ETH, oldCap, newMaxTotalEth);
  }

  /// @inheritdoc IPermitter
  function updateMaxTokensPerBidder(uint256 newMaxTokensPerBidder) external onlyOwner {
    uint256 oldCap = maxTokensPerBidder;
    maxTokensPerBidder = newMaxTokensPerBidder;
    emit CapUpdated(CapType.TOKENS_PER_BIDDER, oldCap, newMaxTokensPerBidder);
  }

  /// @inheritdoc IPermitter
  function updateTrustedSigner(address newSigner) external onlyOwner {
    if (newSigner == address(0)) revert InvalidTrustedSigner();
    address oldSigner = trustedSigner;
    trustedSigner = newSigner;
    emit SignerUpdated(oldSigner, newSigner);
  }

  /// @inheritdoc IPermitter
  function pause() external onlyOwner {
    paused = true;
    emit Paused(msg.sender);
  }

  /// @inheritdoc IPermitter
  function unpause() external onlyOwner {
    paused = false;
    emit Unpaused(msg.sender);
  }

  /// @inheritdoc IPermitter
  function getBidAmount(address bidder) external view returns (uint256 cumulativeBid) {
    return cumulativeBids[bidder];
  }

  /// @inheritdoc IPermitter
  function getTotalEthRaised() external view returns (uint256) {
    return totalEthRaised;
  }

  /// @notice Get the EIP-712 domain separator.
  /// @return The domain separator hash.
  function domainSeparator() external view returns (bytes32) {
    return _domainSeparatorV4();
  }

  /// @notice Recover the signer address from a permit and signature.
  /// @param permit The permit struct.
  /// @param signature The EIP-712 signature.
  /// @return The recovered signer address.
  function _recoverSigner(Permit memory permit, bytes memory signature) internal view returns (address) {
    bytes32 structHash =
      keccak256(abi.encode(PERMIT_TYPEHASH, permit.bidder, permit.maxBidAmount, permit.expiry));
    bytes32 digest = _hashTypedDataV4(structHash);
    return ECDSA.recover(digest, signature);
  }
}
