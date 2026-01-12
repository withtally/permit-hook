// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {PermitterFactory} from "src/PermitterFactory.sol";
import {Permitter} from "src/Permitter.sol";
import {IPermitter} from "src/interfaces/IPermitter.sol";

/// @notice Integration tests for the full Permitter system.
contract IntegrationTest is Test {
  PermitterFactory public factory;
  Permitter public permitter;

  // Test accounts
  address public deployer = makeAddr("deployer");
  address public auctionOwner = makeAddr("auctionOwner");
  address public trustedSigner;
  uint256 public signerPrivateKey;
  address public authorizedCaller = makeAddr("ccaContract");

  address public bidder1 = makeAddr("bidder1");
  address public bidder2 = makeAddr("bidder2");
  address public bidder3 = makeAddr("bidder3");

  // Auction configuration
  uint256 public constant MAX_TOTAL_ETH = 100 ether;
  uint256 public constant MAX_TOKENS_PER_BIDDER = 1000 ether;
  uint256 public constant MIN_TOKENS_PER_BIDDER = 10 ether;
  bytes32 public constant AUCTION_SALT = bytes32(uint256(1));

  // EIP-712 constants
  bytes32 public constant PERMIT_TYPEHASH = keccak256("Permit(address bidder,uint256 expiry)");

  function setUp() public virtual {
    // Create a trusted signer with a known private key
    signerPrivateKey = 0x1234;
    trustedSigner = vm.addr(signerPrivateKey);

    // Deploy the factory
    factory = new PermitterFactory();

    // Deploy a Permitter for a specific auction
    vm.prank(deployer);
    address permitterAddress = factory.createPermitter(
      trustedSigner,
      MAX_TOTAL_ETH,
      MAX_TOKENS_PER_BIDDER,
      MIN_TOKENS_PER_BIDDER,
      auctionOwner,
      authorizedCaller,
      AUCTION_SALT
    );
    permitter = Permitter(permitterAddress);
  }

  /// @notice Helper function to create a valid permit signature.
  function _createPermitSignature(address _bidder, uint256 _expiry)
    internal
    view
    returns (bytes memory permitData)
  {
    IPermitter.Permit memory permit = IPermitter.Permit({bidder: _bidder, expiry: _expiry});

    bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, permit.bidder, permit.expiry));

    bytes32 domainSeparator = permitter.domainSeparator();
    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
    bytes memory signature = abi.encodePacked(r, s, v);

    permitData = abi.encode(permit, signature);
  }
}

/// @notice Test a complete auction lifecycle.
contract FullAuctionLifecycle is IntegrationTest {
  function test_CompleteAuctionWithMultipleBidders() public {
    uint256 expiry = block.timestamp + 24 hours;

    // Create permits for all bidders
    bytes memory permit1 = _createPermitSignature(bidder1, expiry);
    bytes memory permit2 = _createPermitSignature(bidder2, expiry);
    bytes memory permit3 = _createPermitSignature(bidder3, expiry);

    // Bidder 1 places multiple bids (via authorized caller)
    vm.startPrank(authorizedCaller);
    permitter.validateBid(bidder1, 100 ether, 10 ether, permit1);
    permitter.validateBid(bidder1, 150 ether, 15 ether, permit1);

    assertEq(permitter.getBidAmount(bidder1), 250 ether);
    assertEq(permitter.getTotalEthRaised(), 25 ether);

    // Bidder 2 places a bid
    permitter.validateBid(bidder2, 200 ether, 20 ether, permit2);

    assertEq(permitter.getBidAmount(bidder2), 200 ether);
    assertEq(permitter.getTotalEthRaised(), 45 ether);

    // Bidder 3 places multiple bids
    permitter.validateBid(bidder3, 100 ether, 10 ether, permit3);
    permitter.validateBid(bidder3, 200 ether, 20 ether, permit3);

    assertEq(permitter.getBidAmount(bidder3), 300 ether);
    assertEq(permitter.getTotalEthRaised(), 75 ether);

    // Bidder 1 places another bid
    permitter.validateBid(bidder1, 100 ether, 10 ether, permit1);

    assertEq(permitter.getBidAmount(bidder1), 350 ether);
    assertEq(permitter.getTotalEthRaised(), 85 ether);
    vm.stopPrank();

    // Verify final state
    assertEq(permitter.getBidAmount(bidder1), 350 ether);
    assertEq(permitter.getBidAmount(bidder2), 200 ether);
    assertEq(permitter.getBidAmount(bidder3), 300 ether);
    assertEq(permitter.getTotalEthRaised(), 85 ether);
  }

  function test_AuctionReachesTotalCap() public {
    uint256 expiry = block.timestamp + 24 hours;

    bytes memory permit1 = _createPermitSignature(bidder1, expiry);
    bytes memory permit2 = _createPermitSignature(bidder2, expiry);

    vm.startPrank(authorizedCaller);

    // Fill up most of the cap
    permitter.validateBid(bidder1, 100 ether, 50 ether, permit1);
    permitter.validateBid(bidder2, 100 ether, 49 ether, permit2);

    assertEq(permitter.getTotalEthRaised(), 99 ether);

    // Final bid that exactly hits the cap
    permitter.validateBid(bidder1, 10 ether, 1 ether, permit1);

    assertEq(permitter.getTotalEthRaised(), 100 ether);

    // Any more bids should fail (bid amount must be >= MIN_TOKENS_PER_BIDDER)
    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.ExceedsTotalCap.selector, 1 ether, MAX_TOTAL_ETH, 100 ether)
    );
    permitter.validateBid(bidder2, 10 ether, 1 ether, permit2);
    vm.stopPrank();
  }

  function test_BidderReachesPersonalCap() public {
    uint256 expiry = block.timestamp + 24 hours;

    bytes memory permit = _createPermitSignature(bidder1, expiry);

    vm.startPrank(authorizedCaller);

    // Place bids up to the personal cap (MAX_TOKENS_PER_BIDDER = 1000 ether)
    permitter.validateBid(bidder1, 400 ether, 4 ether, permit);
    permitter.validateBid(bidder1, 400 ether, 4 ether, permit);
    permitter.validateBid(bidder1, 200 ether, 2 ether, permit);

    assertEq(permitter.getBidAmount(bidder1), 1000 ether);

    // Next bid should fail
    vm.expectRevert(
      abi.encodeWithSelector(
        IPermitter.ExceedsPersonalCap.selector, 10 ether, MAX_TOKENS_PER_BIDDER, 1000 ether
      )
    );
    permitter.validateBid(bidder1, 10 ether, 0.1 ether, permit);
    vm.stopPrank();
  }
}

/// @notice Test emergency scenarios.
contract EmergencyScenarios is IntegrationTest {
  function test_OwnerPausesAndResumesAuction() public {
    uint256 expiry = block.timestamp + 24 hours;
    bytes memory permit = _createPermitSignature(bidder1, expiry);

    // Place a bid successfully
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder1, 100 ether, 1 ether, permit);

    // Owner pauses the auction
    vm.prank(auctionOwner);
    permitter.pause();

    // Bid should fail while paused
    vm.expectRevert(IPermitter.ContractPaused.selector);
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder1, 100 ether, 1 ether, permit);

    // Owner unpauses
    vm.prank(auctionOwner);
    permitter.unpause();

    // Bid should succeed again
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder1, 100 ether, 1 ether, permit);

    assertEq(permitter.getBidAmount(bidder1), 200 ether);
  }

  function test_SignerKeyRotationWithTimelock() public {
    uint256 expiry = block.timestamp + 2 hours;

    // Place a bid with the original signer
    bytes memory permit = _createPermitSignature(bidder1, expiry);
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder1, 100 ether, 1 ether, permit);

    // Schedule rotation to a new signer
    uint256 newSignerKey = 0x5678;
    address newSigner = vm.addr(newSignerKey);

    vm.prank(auctionOwner);
    permitter.scheduleUpdateTrustedSigner(newSigner);

    // Old permit still works during timelock period (grace period)
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder1, 100 ether, 1 ether, permit);
    assertEq(permitter.getBidAmount(bidder1), 200 ether);

    // Advance past timelock
    vm.warp(block.timestamp + 1 hours + 1);

    // Execute the signer update
    vm.prank(auctionOwner);
    permitter.executeUpdateTrustedSigner();

    // Old permit should fail now
    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.InvalidSignature.selector, newSigner, trustedSigner)
    );
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder1, 100 ether, 1 ether, permit);

    // Create a new permit with the new signer
    IPermitter.Permit memory newPermitStruct = IPermitter.Permit({bidder: bidder1, expiry: expiry});

    bytes32 structHash =
      keccak256(abi.encode(PERMIT_TYPEHASH, newPermitStruct.bidder, newPermitStruct.expiry));

    bytes32 domainSeparator = permitter.domainSeparator();
    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(newSignerKey, digest);
    bytes memory newSignature = abi.encodePacked(r, s, v);
    bytes memory newPermitData = abi.encode(newPermitStruct, newSignature);

    // New permit should work
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder1, 100 ether, 1 ether, newPermitData);

    assertEq(permitter.getBidAmount(bidder1), 300 ether);
  }

  function test_OwnerAdjustsCapsWithTimelock() public {
    uint256 expiry = block.timestamp + 2 hours;
    bytes memory permit = _createPermitSignature(bidder1, expiry);

    // Place initial bids
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder1, 400 ether, 40 ether, permit);

    // Owner schedules cap reduction
    vm.prank(auctionOwner);
    permitter.scheduleUpdateMaxTotalEth(50 ether);

    // During timelock, old cap still applies - bid succeeds
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder1, 50 ether, 5 ether, permit);

    // Advance past timelock
    vm.warp(block.timestamp + 1 hours + 1);

    // Execute cap update
    vm.prank(auctionOwner);
    permitter.executeUpdateMaxTotalEth();

    // Now the new cap applies - next bid exceeds it
    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.ExceedsTotalCap.selector, 10 ether, 50 ether, 45 ether)
    );
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder1, 100 ether, 10 ether, permit);

    // But a smaller bid should work
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder1, 50 ether, 5 ether, permit);

    assertEq(permitter.getTotalEthRaised(), 50 ether);
  }

  function test_OwnerRaisesCapWithTimelock() public {
    uint256 expiry = block.timestamp + 3 hours;
    bytes memory permit = _createPermitSignature(bidder1, expiry);

    // Schedule a low initial cap
    vm.prank(auctionOwner);
    permitter.scheduleUpdateMaxTotalEth(10 ether);

    vm.warp(block.timestamp + 1 hours + 1);

    vm.prank(auctionOwner);
    permitter.executeUpdateMaxTotalEth();

    // Place bids up to the cap
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder1, 100 ether, 10 ether, permit);

    // Next bid fails
    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.ExceedsTotalCap.selector, 1 ether, 10 ether, 10 ether)
    );
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder1, 10 ether, 1 ether, permit);

    // Owner schedules cap increase
    vm.prank(auctionOwner);
    permitter.scheduleUpdateMaxTotalEth(100 ether);

    vm.warp(block.timestamp + 1 hours + 1);

    vm.prank(auctionOwner);
    permitter.executeUpdateMaxTotalEth();

    // Now the bid succeeds
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder1, 100 ether, 10 ether, permit);

    assertEq(permitter.getTotalEthRaised(), 20 ether);
  }
}

/// @notice Test permit expiry scenarios.
contract PermitExpiry is IntegrationTest {
  function test_PermitExpiresAfterTimestamp() public {
    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permit = _createPermitSignature(bidder1, expiry);

    // Bid succeeds before expiry
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder1, 100 ether, 1 ether, permit);

    // Warp past expiry
    vm.warp(expiry + 1);

    // Bid fails after expiry
    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.SignatureExpired.selector, expiry, block.timestamp)
    );
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder1, 100 ether, 1 ether, permit);
  }

  function test_BidderCanGetNewPermitAfterExpiry() public {
    uint256 expiry1 = block.timestamp + 1 hours;
    bytes memory permit1 = _createPermitSignature(bidder1, expiry1);

    // Use first permit
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder1, 100 ether, 1 ether, permit1);

    // Warp past first expiry
    vm.warp(expiry1 + 1);

    // First permit is now expired
    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.SignatureExpired.selector, expiry1, block.timestamp)
    );
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder1, 100 ether, 1 ether, permit1);

    // Get a new permit with new expiry
    uint256 expiry2 = block.timestamp + 24 hours;
    bytes memory permit2 = _createPermitSignature(bidder1, expiry2);

    // New permit works
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder1, 100 ether, 1 ether, permit2);

    assertEq(permitter.getBidAmount(bidder1), 200 ether);
  }
}

/// @notice Test multiple auctions scenario.
contract MultipleAuctions is IntegrationTest {
  Permitter public permitter2;
  Permitter public permitter3;
  address public authorizedCaller2 = makeAddr("ccaContract2");
  address public authorizedCaller3 = makeAddr("ccaContract3");

  function setUp() public override {
    super.setUp();

    // Deploy additional permitters for different auctions
    vm.startPrank(deployer);
    address permitter2Address = factory.createPermitter(
      trustedSigner,
      50 ether,
      500 ether,
      5 ether,
      auctionOwner,
      authorizedCaller2,
      bytes32(uint256(2))
    );
    address permitter3Address = factory.createPermitter(
      trustedSigner,
      200 ether,
      2000 ether,
      20 ether,
      auctionOwner,
      authorizedCaller3,
      bytes32(uint256(3))
    );
    vm.stopPrank();

    permitter2 = Permitter(permitter2Address);
    permitter3 = Permitter(permitter3Address);
  }

  function test_BidderParticipatesInMultipleAuctions() public {
    uint256 expiry = block.timestamp + 24 hours;

    // Create permits for each auction (each has its own domain separator)
    bytes memory permit1 = _createPermitSignatureForPermitter(bidder1, expiry, permitter);
    bytes memory permit2 = _createPermitSignatureForPermitter(bidder1, expiry, permitter2);
    bytes memory permit3 = _createPermitSignatureForPermitter(bidder1, expiry, permitter3);

    // Bid in all auctions (each via their respective authorized caller)
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder1, 100 ether, 10 ether, permit1);

    vm.prank(authorizedCaller2);
    permitter2.validateBid(bidder1, 200 ether, 20 ether, permit2);

    vm.prank(authorizedCaller3);
    permitter3.validateBid(bidder1, 500 ether, 50 ether, permit3);

    // Verify each auction has independent state
    assertEq(permitter.getBidAmount(bidder1), 100 ether);
    assertEq(permitter2.getBidAmount(bidder1), 200 ether);
    assertEq(permitter3.getBidAmount(bidder1), 500 ether);

    assertEq(permitter.getTotalEthRaised(), 10 ether);
    assertEq(permitter2.getTotalEthRaised(), 20 ether);
    assertEq(permitter3.getTotalEthRaised(), 50 ether);
  }

  function test_PermitFromOneAuctionCannotBeUsedInAnother() public {
    uint256 expiry = block.timestamp + 24 hours;

    // Create permit for auction 1
    bytes memory permit1 = _createPermitSignatureForPermitter(bidder1, expiry, permitter);

    // Try to use it in auction 2 - should fail because domain separator is different
    vm.expectRevert();
    vm.prank(authorizedCaller2);
    permitter2.validateBid(bidder1, 100 ether, 10 ether, permit1);
  }

  function _createPermitSignatureForPermitter(
    address _bidder,
    uint256 _expiry,
    Permitter _permitter
  ) internal view returns (bytes memory permitData) {
    IPermitter.Permit memory permit = IPermitter.Permit({bidder: _bidder, expiry: _expiry});

    bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, permit.bidder, permit.expiry));

    bytes32 domainSeparator = _permitter.domainSeparator();
    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
    bytes memory signature = abi.encodePacked(r, s, v);

    permitData = abi.encode(permit, signature);
  }
}
