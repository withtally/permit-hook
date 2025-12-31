// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {PermitterFactory} from "src/PermitterFactory.sol";
import {Permitter} from "src/Permitter.sol";
import {IPermitterFactory} from "src/interfaces/IPermitterFactory.sol";
import {IPermitter} from "src/interfaces/IPermitter.sol";

/// @notice Base test contract for PermitterFactory tests.
contract PermitterFactoryTest is Test {
  PermitterFactory public factory;

  // Test accounts
  address public deployer = makeAddr("deployer");
  address public owner = makeAddr("owner");
  address public trustedSigner = makeAddr("trustedSigner");
  address public authorizedCaller = makeAddr("authorizedCaller");

  // Default configuration
  uint256 public constant MAX_TOTAL_ETH = 100 ether;
  uint256 public constant MAX_TOKENS_PER_BIDDER = 1000 ether;
  bytes32 public constant DEFAULT_SALT = bytes32(uint256(1));

  function setUp() public virtual {
    factory = new PermitterFactory();
  }
}

/// @notice Tests for createPermitter function.
contract CreatePermitter is PermitterFactoryTest {
  function test_DeploysPermitterWithCorrectParameters() public {
    vm.prank(deployer);
    address permitterAddress = factory.createPermitter(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, authorizedCaller, DEFAULT_SALT
    );

    Permitter permitter = Permitter(permitterAddress);

    assertEq(permitter.trustedSigner(), trustedSigner);
    assertEq(permitter.maxTotalEth(), MAX_TOTAL_ETH);
    assertEq(permitter.maxTokensPerBidder(), MAX_TOKENS_PER_BIDDER);
    assertEq(permitter.owner(), owner);
    assertEq(permitter.authorizedCaller(), authorizedCaller);
    assertEq(permitter.paused(), false);
    assertEq(permitter.totalEthRaised(), 0);
  }

  function test_EmitsPermitterCreatedEvent() public {
    vm.prank(deployer);

    // We can't predict the exact address before the call, so we just check the event is emitted
    // with correct parameters
    vm.expectEmit(false, true, true, true);
    emit IPermitterFactory.PermitterCreated(
      address(0), // We don't know the address yet
      owner,
      trustedSigner,
      authorizedCaller,
      MAX_TOTAL_ETH,
      MAX_TOKENS_PER_BIDDER
    );

    factory.createPermitter(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, authorizedCaller, DEFAULT_SALT
    );
  }

  function test_SameSaltFromDifferentSendersCreatesDifferentAddresses() public {
    address deployer2 = makeAddr("deployer2");

    vm.prank(deployer);
    address permitter1 = factory.createPermitter(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, authorizedCaller, DEFAULT_SALT
    );

    vm.prank(deployer2);
    address permitter2 = factory.createPermitter(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, authorizedCaller, DEFAULT_SALT
    );

    assertTrue(permitter1 != permitter2);
  }

  function test_DifferentSaltFromSameSenderCreatesDifferentAddresses() public {
    bytes32 salt1 = bytes32(uint256(1));
    bytes32 salt2 = bytes32(uint256(2));

    vm.startPrank(deployer);
    address permitter1 = factory.createPermitter(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, authorizedCaller, salt1
    );
    address permitter2 = factory.createPermitter(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, authorizedCaller, salt2
    );
    vm.stopPrank();

    assertTrue(permitter1 != permitter2);
  }

  function test_RevertIf_TrustedSignerIsZero() public {
    vm.expectRevert(IPermitter.InvalidTrustedSigner.selector);
    vm.prank(deployer);
    factory.createPermitter(
      address(0), MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, authorizedCaller, DEFAULT_SALT
    );
  }

  function test_RevertIf_OwnerIsZero() public {
    vm.expectRevert(IPermitter.InvalidOwner.selector);
    vm.prank(deployer);
    factory.createPermitter(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, address(0), authorizedCaller, DEFAULT_SALT
    );
  }

  function test_RevertIf_MaxTotalEthIsZero() public {
    vm.expectRevert(IPermitter.InvalidCap.selector);
    vm.prank(deployer);
    factory.createPermitter(
      trustedSigner, 0, MAX_TOKENS_PER_BIDDER, owner, authorizedCaller, DEFAULT_SALT
    );
  }

  function test_RevertIf_MaxTokensPerBidderIsZero() public {
    vm.expectRevert(IPermitter.InvalidCap.selector);
    vm.prank(deployer);
    factory.createPermitter(
      trustedSigner, MAX_TOTAL_ETH, 0, owner, authorizedCaller, DEFAULT_SALT
    );
  }
}

/// @notice Tests for predictPermitterAddress function.
contract PredictPermitterAddress is PermitterFactoryTest {
  function test_PredictedAddressMatchesActualDeployment() public {
    vm.startPrank(deployer);

    address predicted = factory.predictPermitterAddress(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, authorizedCaller, DEFAULT_SALT
    );

    address actual = factory.createPermitter(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, authorizedCaller, DEFAULT_SALT
    );

    vm.stopPrank();

    assertEq(predicted, actual);
  }

  function test_DifferentParametersProduceDifferentAddresses() public {
    vm.startPrank(deployer);

    address addr1 = factory.predictPermitterAddress(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, authorizedCaller, DEFAULT_SALT
    );

    address addr2 = factory.predictPermitterAddress(
      trustedSigner, MAX_TOTAL_ETH + 1, MAX_TOKENS_PER_BIDDER, owner, authorizedCaller, DEFAULT_SALT
    );

    address addr3 = factory.predictPermitterAddress(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER + 1, owner, authorizedCaller, DEFAULT_SALT
    );

    address differentOwner = makeAddr("differentOwner");
    address addr4 = factory.predictPermitterAddress(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, differentOwner, authorizedCaller, DEFAULT_SALT
    );

    address differentSigner = makeAddr("differentSigner");
    address addr5 = factory.predictPermitterAddress(
      differentSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, authorizedCaller, DEFAULT_SALT
    );

    address differentCaller = makeAddr("differentCaller");
    address addr6 = factory.predictPermitterAddress(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, differentCaller, DEFAULT_SALT
    );

    vm.stopPrank();

    // All addresses should be different
    assertTrue(addr1 != addr2);
    assertTrue(addr1 != addr3);
    assertTrue(addr1 != addr4);
    assertTrue(addr1 != addr5);
    assertTrue(addr1 != addr6);
    assertTrue(addr2 != addr3);
    assertTrue(addr2 != addr4);
    assertTrue(addr2 != addr5);
    assertTrue(addr3 != addr4);
    assertTrue(addr3 != addr5);
    assertTrue(addr4 != addr5);
  }

  function test_SameSenderSameParamsProduceSameAddress() public {
    vm.startPrank(deployer);

    address addr1 = factory.predictPermitterAddress(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, authorizedCaller, DEFAULT_SALT
    );

    address addr2 = factory.predictPermitterAddress(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, authorizedCaller, DEFAULT_SALT
    );

    vm.stopPrank();

    assertEq(addr1, addr2);
  }

  function test_DifferentSendersProduceDifferentAddresses() public {
    address deployer2 = makeAddr("deployer2");

    vm.prank(deployer);
    address addr1 = factory.predictPermitterAddress(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, authorizedCaller, DEFAULT_SALT
    );

    vm.prank(deployer2);
    address addr2 = factory.predictPermitterAddress(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, authorizedCaller, DEFAULT_SALT
    );

    assertTrue(addr1 != addr2);
  }
}

/// @notice Tests for multiple deployments.
contract MultipleDeployments is PermitterFactoryTest {
  function test_DeployMultiplePermittersForSameOwner() public {
    bytes32 salt1 = bytes32(uint256(1));
    bytes32 salt2 = bytes32(uint256(2));
    bytes32 salt3 = bytes32(uint256(3));

    vm.startPrank(deployer);

    address permitter1 =
      factory.createPermitter(trustedSigner, 50 ether, 500 ether, owner, authorizedCaller, salt1);
    address permitter2 =
      factory.createPermitter(trustedSigner, 100 ether, 1000 ether, owner, authorizedCaller, salt2);
    address permitter3 =
      factory.createPermitter(trustedSigner, 200 ether, 2000 ether, owner, authorizedCaller, salt3);

    vm.stopPrank();

    // Verify all are different addresses
    assertTrue(permitter1 != permitter2);
    assertTrue(permitter2 != permitter3);
    assertTrue(permitter1 != permitter3);

    // Verify each has correct configuration
    assertEq(Permitter(permitter1).maxTotalEth(), 50 ether);
    assertEq(Permitter(permitter2).maxTotalEth(), 100 ether);
    assertEq(Permitter(permitter3).maxTotalEth(), 200 ether);

    assertEq(Permitter(permitter1).maxTokensPerBidder(), 500 ether);
    assertEq(Permitter(permitter2).maxTokensPerBidder(), 1000 ether);
    assertEq(Permitter(permitter3).maxTokensPerBidder(), 2000 ether);
  }

  function test_DeployPermittersWithDifferentOwners() public {
    address owner1 = makeAddr("owner1");
    address owner2 = makeAddr("owner2");

    vm.startPrank(deployer);

    address permitter1 = factory.createPermitter(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner1, authorizedCaller, bytes32(uint256(1))
    );
    address permitter2 = factory.createPermitter(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner2, authorizedCaller, bytes32(uint256(2))
    );

    vm.stopPrank();

    assertEq(Permitter(permitter1).owner(), owner1);
    assertEq(Permitter(permitter2).owner(), owner2);

    // Verify owner1 can modify permitter1 but not permitter2
    vm.prank(owner1);
    Permitter(permitter1).pause();
    assertTrue(Permitter(permitter1).paused());

    vm.expectRevert(IPermitter.Unauthorized.selector);
    vm.prank(owner1);
    Permitter(permitter2).pause();
  }

  function test_DeployPermittersWithDifferentSigners() public {
    address signer1 = makeAddr("signer1");
    address signer2 = makeAddr("signer2");

    vm.startPrank(deployer);

    address permitter1 = factory.createPermitter(
      signer1, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, authorizedCaller, bytes32(uint256(1))
    );
    address permitter2 = factory.createPermitter(
      signer2, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, authorizedCaller, bytes32(uint256(2))
    );

    vm.stopPrank();

    assertEq(Permitter(permitter1).trustedSigner(), signer1);
    assertEq(Permitter(permitter2).trustedSigner(), signer2);
  }

  function test_DeployPermittersWithDifferentAuthorizedCallers() public {
    address caller1 = makeAddr("caller1");
    address caller2 = makeAddr("caller2");

    vm.startPrank(deployer);

    address permitter1 = factory.createPermitter(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, caller1, bytes32(uint256(1))
    );
    address permitter2 = factory.createPermitter(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, caller2, bytes32(uint256(2))
    );

    vm.stopPrank();

    assertEq(Permitter(permitter1).authorizedCaller(), caller1);
    assertEq(Permitter(permitter2).authorizedCaller(), caller2);
  }
}
