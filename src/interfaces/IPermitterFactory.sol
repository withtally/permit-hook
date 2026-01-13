// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @title IPermitterFactory
/// @notice Factory interface for deploying isolated Permitter instances for each auction using
/// CREATE2 for deterministic addresses.
interface IPermitterFactory {
  /// @notice Emitted when a new Permitter is created.
  /// @param permitter The address of the deployed Permitter contract.
  /// @param owner The address that can update caps and pause.
  /// @param trustedSigner The address authorized to sign permits.
  /// @param authorizedCaller The CCA contract authorized to call validateBid.
  /// @param maxTotalEth The maximum total ETH that can be raised.
  /// @param maxTokensPerBidder The maximum tokens any single bidder can purchase.
  /// @param minTokensPerBidder The minimum tokens any single bidder must purchase per bid.
  event PermitterCreated(
    address indexed permitter,
    address indexed owner,
    address indexed trustedSigner,
    address authorizedCaller,
    uint256 maxTotalEth,
    uint256 maxTokensPerBidder,
    uint256 minTokensPerBidder
  );

  /// @notice Create a new Permitter instance for an auction.
  /// @param trustedSigner Address authorized to sign permits (Tally backend).
  /// @param maxTotalEth Maximum total ETH that can be raised in the auction.
  /// @param maxTokensPerBidder Maximum tokens any single bidder can purchase.
  /// @param minTokensPerBidder Minimum tokens any single bidder must purchase per bid.
  /// @param owner Address that can update caps and pause (auction creator).
  /// @param authorizedCaller CCA contract address authorized to call validateBid.
  /// @param salt Salt for CREATE2 deployment to enable deterministic addresses.
  /// @return permitter Address of deployed Permitter contract.
  function createPermitter(
    address trustedSigner,
    uint256 maxTotalEth,
    uint256 maxTokensPerBidder,
    uint256 minTokensPerBidder,
    address owner,
    address authorizedCaller,
    bytes32 salt
  ) external returns (address permitter);

  /// @notice Predict the address of a Permitter before deployment.
  /// @param trustedSigner Address authorized to sign permits.
  /// @param maxTotalEth Maximum total ETH that can be raised.
  /// @param maxTokensPerBidder Maximum tokens any single bidder can purchase.
  /// @param minTokensPerBidder Minimum tokens any single bidder must purchase per bid.
  /// @param owner Address that can update caps and pause.
  /// @param authorizedCaller CCA contract address authorized to call validateBid.
  /// @param salt Salt for CREATE2 deployment.
  /// @return The predicted address of the Permitter.
  function predictPermitterAddress(
    address trustedSigner,
    uint256 maxTotalEth,
    uint256 maxTokensPerBidder,
    uint256 minTokensPerBidder,
    address owner,
    address authorizedCaller,
    bytes32 salt
  ) external view returns (address);
}
