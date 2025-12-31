// SPDX-License-Identifier: UNLICENSED
// slither-disable-start reentrancy-benign

pragma solidity 0.8.30;

import {Script} from "forge-std/Script.sol";
import {PermitterFactory} from "src/PermitterFactory.sol";

/// @notice Deployment script for the PermitterFactory contract.
/// @dev The factory is deployed with CREATE2 to ensure the same address across all chains.
contract Deploy is Script {
  /// @notice Deploys the PermitterFactory contract.
  /// @return factory The deployed PermitterFactory contract.
  function run() public returns (PermitterFactory factory) {
    vm.broadcast();
    factory = new PermitterFactory();
  }
}
