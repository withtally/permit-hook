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
  bytes32 public constant PERMIT_TYPEHASH = keccak256("Permit(address bidder,uint256 expiry)");

  /// @notice Timelock delay for parameter updates (1 hour).
  uint256 public constant UPDATE_DELAY = 1 hours;

  /// @notice Address authorized to sign permits.
  address public trustedSigner;

  /// @notice Maximum total ETH that can be raised.
  uint256 public maxTotalEth;

  /// @notice Maximum tokens any single bidder can purchase.
  uint256 public maxTokensPerBidder;

  /// @notice Minimum tokens any single bidder must purchase per bid.
  uint256 public minTokensPerBidder;

  /// @notice Cumulative bid amounts per address.
  mapping(address bidder => uint256 amount) public cumulativeBids;

  /// @notice Total ETH raised across all bidders.
  uint256 public totalEthRaised;

  /// @notice Owner address that can update caps and pause.
  address public owner;

  /// @notice Whether the contract is paused.
  bool public paused;

  /// @notice Authorized caller (CCA contract) that can call validateBid.
  address public authorizedCaller;

  /// @notice Pending maxTotalEth update value.
  uint256 public pendingMaxTotalEth;

  /// @notice Time when pending maxTotalEth update can be executed.
  uint256 public pendingMaxTotalEthTime;

  /// @notice Pending maxTokensPerBidder update value.
  uint256 public pendingMaxTokensPerBidder;

  /// @notice Time when pending maxTokensPerBidder update can be executed.
  uint256 public pendingMaxTokensPerBidderTime;

  /// @notice Pending trustedSigner update address.
  address public pendingTrustedSigner;

  /// @notice Time when pending trustedSigner update can be executed.
  uint256 public pendingTrustedSignerTime;

  /// @notice Modifier to restrict access to owner only.
  modifier onlyOwner() {
    if (msg.sender != owner) revert Unauthorized();
    _;
  }

  /// @notice Creates a new Permitter instance.
  /// @param _trustedSigner Address authorized to sign permits.
  /// @param _maxTotalEth Maximum total ETH that can be raised.
  /// @param _maxTokensPerBidder Maximum tokens any single bidder can purchase.
  /// @param _minTokensPerBidder Minimum tokens any single bidder must purchase per bid.
  /// @param _owner Address that can update caps and pause.
  /// @param _authorizedCaller CCA contract authorized to call validateBid.
  constructor(
    address _trustedSigner,
    uint256 _maxTotalEth,
    uint256 _maxTokensPerBidder,
    uint256 _minTokensPerBidder,
    address _owner,
    address _authorizedCaller
  ) EIP712("Permitter", "1") {
    if (_trustedSigner == address(0)) revert InvalidTrustedSigner();
    if (_owner == address(0)) revert InvalidOwner();
    if (_maxTotalEth == 0) revert InvalidCap();
    if (_maxTokensPerBidder == 0) revert InvalidCap();

    trustedSigner = _trustedSigner;
    maxTotalEth = _maxTotalEth;
    maxTokensPerBidder = _maxTokensPerBidder;
    minTokensPerBidder = _minTokensPerBidder;
    owner = _owner;
    authorizedCaller = _authorizedCaller;
  }

  /// @inheritdoc IPermitter
  function validateBid(
    address bidder,
    uint256 bidAmount,
    uint256 ethValue,
    bytes calldata permitData
  ) external returns (bool valid) {
    // 0. Check caller is authorized CCA contract
    if (msg.sender != authorizedCaller) revert UnauthorizedCaller();

    // 1. CHEAPEST: Check if paused
    if (paused) revert ContractPaused();

    // 2. CHEAP: Check minimum bid amount
    if (bidAmount < minTokensPerBidder) {
      revert BidBelowMinimum(bidAmount, minTokensPerBidder);
    }

    // 3. Decode permit data
    (Permit memory permit, bytes memory signature) = abi.decode(permitData, (Permit, bytes));

    // 4. CHEAP: Check time window
    if (block.timestamp > permit.expiry) {
      revert SignatureExpired(permit.expiry, block.timestamp);
    }

    // 5. MODERATE: Verify EIP-712 signature
    address recovered = _recoverSigner(permit, signature);
    if (recovered != trustedSigner) revert InvalidSignature(trustedSigner, recovered);

    // 6. Check permit is for this bidder
    if (permit.bidder != bidder) revert InvalidSignature(bidder, permit.bidder);

    // 7. STORAGE READ: Check individual cap using maxTokensPerBidder
    uint256 alreadyBid = cumulativeBids[bidder];
    uint256 newCumulative = alreadyBid + bidAmount;
    if (newCumulative > maxTokensPerBidder) {
      revert ExceedsPersonalCap(bidAmount, maxTokensPerBidder, alreadyBid);
    }

    // 8. STORAGE READ: Check global cap
    uint256 alreadyRaised = totalEthRaised;
    uint256 newTotalEth = alreadyRaised + ethValue;
    if (newTotalEth > maxTotalEth) revert ExceedsTotalCap(ethValue, maxTotalEth, alreadyRaised);

    // 9. STORAGE WRITE: Update state
    cumulativeBids[bidder] = newCumulative;
    totalEthRaised = newTotalEth;

    // 10. Emit event for monitoring
    emit PermitVerified(
      bidder, bidAmount, maxTokensPerBidder - newCumulative, maxTotalEth - newTotalEth
    );

    return true;
  }

  /// @inheritdoc IPermitter
  function scheduleUpdateMaxTotalEth(uint256 newMaxTotalEth) external onlyOwner {
    if (newMaxTotalEth == 0) revert InvalidCap();

    uint256 executeTime = block.timestamp + UPDATE_DELAY;
    pendingMaxTotalEth = newMaxTotalEth;
    pendingMaxTotalEthTime = executeTime;

    emit CapUpdateScheduled(CapType.TOTAL_ETH, newMaxTotalEth, executeTime);
  }

  /// @inheritdoc IPermitter
  function executeUpdateMaxTotalEth() external onlyOwner {
    if (pendingMaxTotalEthTime == 0) revert UpdateNotScheduled();
    if (block.timestamp < pendingMaxTotalEthTime) {
      revert UpdateTooEarly(pendingMaxTotalEthTime, block.timestamp);
    }
    if (pendingMaxTotalEth < totalEthRaised) {
      revert CapBelowCurrentAmount(pendingMaxTotalEth, totalEthRaised);
    }

    uint256 oldCap = maxTotalEth;
    maxTotalEth = pendingMaxTotalEth;

    // Clear pending update
    pendingMaxTotalEth = 0;
    pendingMaxTotalEthTime = 0;

    emit CapUpdated(CapType.TOTAL_ETH, oldCap, maxTotalEth);
  }

  /// @inheritdoc IPermitter
  function scheduleUpdateMaxTokensPerBidder(uint256 newMaxTokensPerBidder) external onlyOwner {
    if (newMaxTokensPerBidder == 0) revert InvalidCap();

    uint256 executeTime = block.timestamp + UPDATE_DELAY;
    pendingMaxTokensPerBidder = newMaxTokensPerBidder;
    pendingMaxTokensPerBidderTime = executeTime;

    emit CapUpdateScheduled(CapType.TOKENS_PER_BIDDER, newMaxTokensPerBidder, executeTime);
  }

  /// @inheritdoc IPermitter
  function executeUpdateMaxTokensPerBidder() external onlyOwner {
    if (pendingMaxTokensPerBidderTime == 0) revert UpdateNotScheduled();
    if (block.timestamp < pendingMaxTokensPerBidderTime) {
      revert UpdateTooEarly(pendingMaxTokensPerBidderTime, block.timestamp);
    }

    uint256 oldCap = maxTokensPerBidder;
    maxTokensPerBidder = pendingMaxTokensPerBidder;

    // Clear pending update
    pendingMaxTokensPerBidder = 0;
    pendingMaxTokensPerBidderTime = 0;

    emit CapUpdated(CapType.TOKENS_PER_BIDDER, oldCap, maxTokensPerBidder);
  }

  /// @inheritdoc IPermitter
  function scheduleUpdateTrustedSigner(address newSigner) external onlyOwner {
    if (newSigner == address(0)) revert InvalidTrustedSigner();

    uint256 executeTime = block.timestamp + UPDATE_DELAY;
    pendingTrustedSigner = newSigner;
    pendingTrustedSignerTime = executeTime;

    emit SignerUpdateScheduled(newSigner, executeTime);
  }

  /// @inheritdoc IPermitter
  function executeUpdateTrustedSigner() external onlyOwner {
    if (pendingTrustedSignerTime == 0) revert UpdateNotScheduled();
    if (block.timestamp < pendingTrustedSignerTime) {
      revert UpdateTooEarly(pendingTrustedSignerTime, block.timestamp);
    }

    address oldSigner = trustedSigner;
    trustedSigner = pendingTrustedSigner;

    // Clear pending update
    pendingTrustedSigner = address(0);
    pendingTrustedSignerTime = 0;

    emit SignerUpdated(oldSigner, trustedSigner);
  }

  /// @inheritdoc IPermitter
  function updateAuthorizedCaller(address newCaller) external onlyOwner {
    address oldCaller = authorizedCaller;
    authorizedCaller = newCaller;
    emit AuthorizedCallerUpdated(oldCaller, newCaller);
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
  function _recoverSigner(Permit memory permit, bytes memory signature)
    internal
    view
    returns (address)
  {
    bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, permit.bidder, permit.expiry));
    bytes32 digest = _hashTypedDataV4(structHash);
    return ECDSA.recover(digest, signature);
  }
}
