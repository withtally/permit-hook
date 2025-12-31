// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @title IPermitter
/// @notice Interface for the Permitter contract that validates bids in CCA auctions using EIP-712
/// signed permits.
interface IPermitter {
  /// @notice Enum for cap types used in events.
  enum CapType {
    TOTAL_ETH,
    TOKENS_PER_BIDDER
  }

  /// @notice The permit structure containing bidder authorization data.
  /// @param bidder Address authorized to bid.
  /// @param maxBidAmount Maximum tokens this bidder can purchase (cumulative).
  /// @param expiry Timestamp when permit expires.
  struct Permit {
    address bidder;
    uint256 maxBidAmount;
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

  /// @notice Emitted when the caller is not authorized.
  error Unauthorized();

  /// @notice Emitted when the trusted signer is the zero address.
  error InvalidTrustedSigner();

  /// @notice Emitted when the owner is the zero address.
  error InvalidOwner();

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

  /// @notice Update the maximum total ETH cap (owner only).
  /// @param newMaxTotalEth New ETH cap.
  function updateMaxTotalEth(uint256 newMaxTotalEth) external;

  /// @notice Update the maximum tokens per bidder cap (owner only).
  /// @param newMaxTokensPerBidder New per-bidder cap.
  function updateMaxTokensPerBidder(uint256 newMaxTokensPerBidder) external;

  /// @notice Update the trusted signer address (owner only).
  /// @dev Use this to rotate keys if signing key is compromised.
  /// @param newSigner New trusted signer address.
  function updateTrustedSigner(address newSigner) external;

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

  /// @notice Get the owner address.
  /// @return The owner address.
  function owner() external view returns (address);

  /// @notice Check if the contract is paused.
  /// @return True if paused, false otherwise.
  function paused() external view returns (bool);
}
