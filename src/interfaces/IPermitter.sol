// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @title IPermitter
/// @notice Interface for the Permitter contract that validates bids in CCA auctions using EIP-712
/// signed permits.
interface IPermitter {
  /// @notice Enum for cap types used in events.
  enum CapType {
    TOTAL_ETH,
    MAX_TOKENS_PER_BIDDER,
    MIN_TOKENS_PER_BIDDER
  }

  /// @notice The permit structure containing bidder authorization data.
  /// @param bidder Address authorized to bid.
  /// @param expiry Timestamp when permit expires.
  struct Permit {
    address bidder;
    uint256 expiry;
  }

  /// @notice Emitted when the contract is paused.
  error ContractPaused();

  /// @notice Emitted when a signature has expired.
  /// @param expiry The expiry timestamp of the signature.
  /// @param currentTime The current block timestamp.
  error SignatureExpired(uint256 expiry, uint256 currentTime);

  /// @notice Emitted when signature verification fails.
  /// @param expected The expected signer address.
  /// @param recovered The recovered signer address.
  error InvalidSignature(address expected, address recovered);

  /// @notice Emitted when a bid would exceed the personal cap.
  /// @param requested The requested bid amount.
  /// @param cap The maximum allowed cap.
  /// @param alreadyBid The amount already bid.
  error ExceedsPersonalCap(uint256 requested, uint256 cap, uint256 alreadyBid);

  /// @notice Emitted when a bid would exceed the total cap.
  /// @param requested The requested bid amount.
  /// @param cap The maximum total cap.
  /// @param alreadyRaised The amount already raised.
  error ExceedsTotalCap(uint256 requested, uint256 cap, uint256 alreadyRaised);

  /// @notice Emitted when a bid is below the minimum amount.
  /// @param bidAmount The bid amount that was attempted.
  /// @param minRequired The minimum required bid amount.
  error BidBelowMinimum(uint256 bidAmount, uint256 minRequired);

  /// @notice Emitted when the caller is not authorized.
  error Unauthorized();

  /// @notice Emitted when the trusted signer is the zero address.
  error InvalidTrustedSigner();

  /// @notice Emitted when the owner is the zero address.
  error InvalidOwner();

  /// @notice Emitted when a cap value is invalid (zero).
  error InvalidCap();

  /// @notice Emitted when minTokensPerBidder exceeds maxTokensPerBidder.
  /// @param minTokens The minimum tokens per bidder.
  /// @param maxTokens The maximum tokens per bidder.
  error MinTokensExceedsMaxTokens(uint256 minTokens, uint256 maxTokens);

  /// @notice Emitted when proposed cap is below current amount.
  /// @param proposed The proposed new cap.
  /// @param current The current amount that would exceed the cap.
  error CapBelowCurrentAmount(uint256 proposed, uint256 current);

  /// @notice Emitted when caller is not the authorized CCA contract.
  error UnauthorizedCaller();

  /// @notice Emitted when trying to execute an update that wasn't scheduled.
  error UpdateNotScheduled();

  /// @notice Emitted when trying to execute an update before the delay has passed.
  /// @param scheduledTime The time when the update can be executed.
  /// @param currentTime The current block timestamp.
  error UpdateTooEarly(uint256 scheduledTime, uint256 currentTime);

  /// @notice Emitted when a permit is successfully verified.
  /// @param bidder The address of the bidder.
  /// @param bidAmount The amount of tokens bid.
  /// @param remainingPersonalCap The remaining tokens the bidder can purchase.
  /// @param remainingTotalCap The remaining ETH that can be raised.
  event PermitVerified(
    address indexed bidder,
    uint256 bidAmount,
    uint256 remainingPersonalCap,
    uint256 remainingTotalCap
  );

  /// @notice Emitted when a cap is updated.
  /// @param capType The type of cap being updated.
  /// @param oldCap The old cap value.
  /// @param newCap The new cap value.
  event CapUpdated(CapType indexed capType, uint256 oldCap, uint256 newCap);

  /// @notice Emitted when the trusted signer is updated.
  /// @param oldSigner The old signer address.
  /// @param newSigner The new signer address.
  event SignerUpdated(address indexed oldSigner, address indexed newSigner);

  /// @notice Emitted when the contract is paused.
  /// @param by The address that paused the contract.
  event Paused(address indexed by);

  /// @notice Emitted when the contract is unpaused.
  /// @param by The address that unpaused the contract.
  event Unpaused(address indexed by);

  /// @notice Emitted when a cap update is scheduled.
  /// @param capType The type of cap being updated.
  /// @param newCap The new cap value to be applied.
  /// @param executeTime The timestamp when the update can be executed.
  event CapUpdateScheduled(CapType indexed capType, uint256 newCap, uint256 executeTime);

  /// @notice Emitted when a signer update is scheduled.
  /// @param newSigner The new signer address to be applied.
  /// @param executeTime The timestamp when the update can be executed.
  event SignerUpdateScheduled(address indexed newSigner, uint256 executeTime);

  /// @notice Emitted when the authorized caller is updated.
  /// @param oldCaller The old authorized caller address.
  /// @param newCaller The new authorized caller address.
  event AuthorizedCallerUpdated(address indexed oldCaller, address indexed newCaller);

  /// @notice Validates a bid in the CCA auction.
  /// @dev Called by CCA contract before accepting bid.
  /// @param bidder Address attempting to place bid.
  /// @param bidAmount Amount of tokens being bid for.
  /// @param ethValue Amount of ETH being bid (passed by CCA contract).
  /// @param permitData ABI-encoded permit signature and metadata.
  /// @return valid True if bid is permitted, reverts otherwise with custom error.
  function validateBid(
    address bidder,
    uint256 bidAmount,
    uint256 ethValue,
    bytes calldata permitData
  ) external returns (bool valid);

  /// @notice Schedule an update to the maximum total ETH cap (owner only).
  /// @dev Update will be executable after UPDATE_DELAY has passed.
  /// @param newMaxTotalEth New ETH cap.
  function scheduleUpdateMaxTotalEth(uint256 newMaxTotalEth) external;

  /// @notice Execute a scheduled update to the maximum total ETH cap (owner only).
  /// @dev Reverts if no update is scheduled or delay hasn't passed.
  function executeUpdateMaxTotalEth() external;

  /// @notice Schedule an update to the maximum tokens per bidder cap (owner only).
  /// @dev Update will be executable after UPDATE_DELAY has passed.
  /// @param newMaxTokensPerBidder New per-bidder cap.
  function scheduleUpdateMaxTokensPerBidder(uint256 newMaxTokensPerBidder) external;

  /// @notice Execute a scheduled update to the maximum tokens per bidder cap (owner only).
  /// @dev Reverts if no update is scheduled or delay hasn't passed.
  function executeUpdateMaxTokensPerBidder() external;

  /// @notice Schedule an update to the minimum tokens per bidder (owner only).
  /// @dev Update will be executable after UPDATE_DELAY has passed.
  /// @param newMinTokensPerBidder New minimum tokens per bidder.
  function scheduleUpdateMinTokensPerBidder(uint256 newMinTokensPerBidder) external;

  /// @notice Execute a scheduled update to the minimum tokens per bidder (owner only).
  /// @dev Reverts if no update is scheduled or delay hasn't passed.
  function executeUpdateMinTokensPerBidder() external;

  /// @notice Schedule an update to the trusted signer address (owner only).
  /// @dev Update will be executable after UPDATE_DELAY has passed.
  /// @param newSigner New trusted signer address.
  function scheduleUpdateTrustedSigner(address newSigner) external;

  /// @notice Execute a scheduled update to the trusted signer (owner only).
  /// @dev Reverts if no update is scheduled or delay hasn't passed.
  function executeUpdateTrustedSigner() external;

  /// @notice Update the authorized caller address (owner only).
  /// @dev No timelock - can be updated immediately for emergency CCA changes.
  /// @param newCaller New authorized caller address.
  function updateAuthorizedCaller(address newCaller) external;

  /// @notice Emergency pause all bid validations (owner only).
  function pause() external;

  /// @notice Resume bid validations (owner only).
  function unpause() external;

  /// @notice Get cumulative bid amount for an address.
  /// @param bidder Address to query.
  /// @return cumulativeBid Total tokens bid by this address.
  function getBidAmount(address bidder) external view returns (uint256 cumulativeBid);

  /// @notice Get total ETH raised across all bidders.
  /// @return totalEthRaised Cumulative ETH raised.
  function getTotalEthRaised() external view returns (uint256 totalEthRaised);

  /// @notice Get the trusted signer address.
  /// @return The trusted signer address.
  function trustedSigner() external view returns (address);

  /// @notice Get the maximum total ETH cap.
  /// @return The maximum total ETH cap.
  function maxTotalEth() external view returns (uint256);

  /// @notice Get the maximum tokens per bidder cap.
  /// @return The maximum tokens per bidder cap.
  function maxTokensPerBidder() external view returns (uint256);

  /// @notice Get the minimum tokens per bidder.
  /// @return The minimum tokens per bidder.
  function minTokensPerBidder() external view returns (uint256);

  /// @notice Get the owner address.
  /// @return The owner address.
  function owner() external view returns (address);

  /// @notice Check if the contract is paused.
  /// @return True if paused, false otherwise.
  function paused() external view returns (bool);

  /// @notice Get the authorized caller address (CCA contract).
  /// @return The authorized caller address.
  function authorizedCaller() external view returns (address);

  /// @notice Get the timelock delay for parameter updates.
  /// @return The delay in seconds.
  function UPDATE_DELAY() external view returns (uint256);

  /// @notice Get the pending max total ETH update.
  /// @return The pending value.
  function pendingMaxTotalEth() external view returns (uint256);

  /// @notice Get the time when pending max total ETH update can be executed.
  /// @return The timestamp.
  function pendingMaxTotalEthTime() external view returns (uint256);

  /// @notice Get the pending max tokens per bidder update.
  /// @return The pending value.
  function pendingMaxTokensPerBidder() external view returns (uint256);

  /// @notice Get the time when pending max tokens per bidder update can be executed.
  /// @return The timestamp.
  function pendingMaxTokensPerBidderTime() external view returns (uint256);

  /// @notice Get the pending min tokens per bidder update.
  /// @return The pending value.
  function pendingMinTokensPerBidder() external view returns (uint256);

  /// @notice Get the time when pending min tokens per bidder update can be executed.
  /// @return The timestamp.
  function pendingMinTokensPerBidderTime() external view returns (uint256);

  /// @notice Get the pending trusted signer update.
  /// @return The pending address.
  function pendingTrustedSigner() external view returns (address);

  /// @notice Get the time when pending trusted signer update can be executed.
  /// @return The timestamp.
  function pendingTrustedSignerTime() external view returns (uint256);
}
