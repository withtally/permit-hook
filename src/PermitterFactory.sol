// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IPermitterFactory} from "./interfaces/IPermitterFactory.sol";
import {Permitter} from "./Permitter.sol";

/// @title PermitterFactory
/// @notice Factory contract for deploying isolated Permitter instances for each auction using
/// CREATE2 for deterministic addresses.
/// @dev Deploy this factory with CREATE2 using the same salt on all chains to get the same factory
/// address across networks.
contract PermitterFactory is IPermitterFactory {
  /// @inheritdoc IPermitterFactory
  function createPermitter(
    address trustedSigner,
    uint256 maxTotalEth,
    uint256 maxTokensPerBidder,
    address owner,
    address authorizedCaller,
    bytes32 salt
  ) external returns (address permitter) {
    // Compute the final salt using the sender address to prevent front-running
    bytes32 finalSalt = keccak256(abi.encodePacked(msg.sender, salt));

    // Deploy the Permitter using CREATE2
    permitter = address(
      new Permitter{salt: finalSalt}(
        trustedSigner, maxTotalEth, maxTokensPerBidder, owner, authorizedCaller
      )
    );

    emit PermitterCreated(
      permitter, owner, trustedSigner, authorizedCaller, maxTotalEth, maxTokensPerBidder
    );
  }

  /// @inheritdoc IPermitterFactory
  function predictPermitterAddress(
    address trustedSigner,
    uint256 maxTotalEth,
    uint256 maxTokensPerBidder,
    address owner,
    address authorizedCaller,
    bytes32 salt
  ) external view returns (address) {
    // Compute the final salt the same way as in createPermitter
    bytes32 finalSalt = keccak256(abi.encodePacked(msg.sender, salt));

    // Compute the init code hash
    bytes memory initCode = abi.encodePacked(
      type(Permitter).creationCode,
      abi.encode(trustedSigner, maxTotalEth, maxTokensPerBidder, owner, authorizedCaller)
    );
    bytes32 initCodeHash = keccak256(initCode);

    // Compute the CREATE2 address
    return address(
      uint160(
        uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), finalSalt, initCodeHash)))
      )
    );
  }
}
