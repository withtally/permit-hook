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

  address public bidder1 = makeAddr("bidder1");
  address public bidder2 = makeAddr("bidder2");
  address public bidder3 = makeAddr("bidder3");

  // Auction configuration
  uint256 public constant MAX_TOTAL_ETH = 100 ether;
  uint256 public constant MAX_TOKENS_PER_BIDDER = 1000 ether;
  bytes32 public constant AUCTION_SALT = bytes32(uint256(1));

  // EIP-712 constants
  bytes32 public constant PERMIT_TYPEHASH =
    keccak256("Permit(address bidder,uint256 maxBidAmount,uint256 expiry)");

  function setUp() public virtual {
    // Create a trusted signer with a known private key
    signerPrivateKey = 0x1234;
    trustedSigner = vm.addr(signerPrivateKey);

    // Deploy the factory
    factory = new PermitterFactory();

    // Deploy a Permitter for a specific auction
    vm.prank(deployer);
    address permitterAddress = factory.createPermitter(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, auctionOwner, AUCTION_SALT
    );
    permitter = Permitter(permitterAddress);
  }

  /// @notice Helper function to create a valid permit signature.
  function _createPermitSignature(address _bidder, uint256 _maxBidAmount, uint256 _expiry)
    internal
    view
    returns (bytes memory permitData)
  {
    IPermitter.Permit memory permit =
      IPermitter.Permit({bidder: _bidder, maxBidAmount: _maxBidAmount, expiry: _expiry});

    bytes32 structHash =
      keccak256(abi.encode(PERMIT_TYPEHASH, permit.bidder, permit.maxBidAmount, permit.expiry));

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
    bytes memory permit1 = _createPermitSignature(bidder1, 400 ether, expiry);
    bytes memory permit2 = _createPermitSignature(bidder2, 300 ether, expiry);
    bytes memory permit3 = _createPermitSignature(bidder3, 500 ether, expiry);

    // Bidder 1 places multiple bids
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

    // Verify final state
    assertEq(permitter.getBidAmount(bidder1), 350 ether);
    assertEq(permitter.getBidAmount(bidder2), 200 ether);
    assertEq(permitter.getBidAmount(bidder3), 300 ether);
    assertEq(permitter.getTotalEthRaised(), 85 ether);
  }

  function test_AuctionReachesTotalCap() public {
    uint256 expiry = block.timestamp + 24 hours;

    bytes memory permit1 = _createPermitSignature(bidder1, MAX_TOKENS_PER_BIDDER, expiry);
    bytes memory permit2 = _createPermitSignature(bidder2, MAX_TOKENS_PER_BIDDER, expiry);

    // Fill up most of the cap
    permitter.validateBid(bidder1, 100 ether, 50 ether, permit1);
    permitter.validateBid(bidder2, 100 ether, 49 ether, permit2);

    assertEq(permitter.getTotalEthRaised(), 99 ether);

    // Final bid that exactly hits the cap
    permitter.validateBid(bidder1, 10 ether, 1 ether, permit1);

    assertEq(permitter.getTotalEthRaised(), 100 ether);

    // Any more bids should fail
    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.ExceedsTotalCap.selector, 1, MAX_TOTAL_ETH, 100 ether)
    );
    permitter.validateBid(bidder2, 1 ether, 1, permit2);
  }

  function test_BidderReachesPersonalCap() public {
    uint256 expiry = block.timestamp + 24 hours;
    uint256 personalCap = 500 ether;

    bytes memory permit = _createPermitSignature(bidder1, personalCap, expiry);

    // Place bids up to the personal cap
    permitter.validateBid(bidder1, 200 ether, 2 ether, permit);
    permitter.validateBid(bidder1, 200 ether, 2 ether, permit);
    permitter.validateBid(bidder1, 100 ether, 1 ether, permit);

    assertEq(permitter.getBidAmount(bidder1), 500 ether);

    // Next bid should fail
    vm.expectRevert(
      abi.encodeWithSelector(
        IPermitter.ExceedsPersonalCap.selector, 1 ether, personalCap, 500 ether
      )
    );
    permitter.validateBid(bidder1, 1 ether, 0.01 ether, permit);
  }
}

/// @notice Test emergency scenarios.
contract EmergencyScenarios is IntegrationTest {
  function test_OwnerPausesAndResumesAuction() public {
    uint256 expiry = block.timestamp + 24 hours;
    bytes memory permit = _createPermitSignature(bidder1, MAX_TOKENS_PER_BIDDER, expiry);

    // Place a bid successfully
    permitter.validateBid(bidder1, 100 ether, 1 ether, permit);

    // Owner pauses the auction
    vm.prank(auctionOwner);
    permitter.pause();

    // Bid should fail while paused
    vm.expectRevert(IPermitter.ContractPaused.selector);
    permitter.validateBid(bidder1, 100 ether, 1 ether, permit);

    // Owner unpauses
    vm.prank(auctionOwner);
    permitter.unpause();

    // Bid should succeed again
    permitter.validateBid(bidder1, 100 ether, 1 ether, permit);

    assertEq(permitter.getBidAmount(bidder1), 200 ether);
  }

  function test_SignerKeyRotation() public {
    uint256 expiry = block.timestamp + 24 hours;

    // Place a bid with the original signer
    bytes memory permit = _createPermitSignature(bidder1, MAX_TOKENS_PER_BIDDER, expiry);
    permitter.validateBid(bidder1, 100 ether, 1 ether, permit);

    // Rotate to a new signer
    uint256 newSignerKey = 0x5678;
    address newSigner = vm.addr(newSignerKey);

    vm.prank(auctionOwner);
    permitter.updateTrustedSigner(newSigner);

    // Old permit should fail
    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.InvalidSignature.selector, newSigner, trustedSigner)
    );
    permitter.validateBid(bidder1, 100 ether, 1 ether, permit);

    // Create a new permit with the new signer
    IPermitter.Permit memory newPermitStruct =
      IPermitter.Permit({bidder: bidder1, maxBidAmount: MAX_TOKENS_PER_BIDDER, expiry: expiry});

    bytes32 structHash = keccak256(
      abi.encode(
        PERMIT_TYPEHASH,
        newPermitStruct.bidder,
        newPermitStruct.maxBidAmount,
        newPermitStruct.expiry
      )
    );

    bytes32 domainSeparator = permitter.domainSeparator();
    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(newSignerKey, digest);
    bytes memory newSignature = abi.encodePacked(r, s, v);
    bytes memory newPermitData = abi.encode(newPermitStruct, newSignature);

    // New permit should work
    permitter.validateBid(bidder1, 100 ether, 1 ether, newPermitData);

    assertEq(permitter.getBidAmount(bidder1), 200 ether);
  }

  function test_OwnerAdjustsCapsLowerDuringAuction() public {
    uint256 expiry = block.timestamp + 24 hours;
    bytes memory permit = _createPermitSignature(bidder1, MAX_TOKENS_PER_BIDDER, expiry);

    // Place initial bids
    permitter.validateBid(bidder1, 400 ether, 40 ether, permit);

    // Owner lowers the total cap
    vm.prank(auctionOwner);
    permitter.updateMaxTotalEth(50 ether);

    // Next bid exceeds the new cap
    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.ExceedsTotalCap.selector, 15 ether, 50 ether, 40 ether)
    );
    permitter.validateBid(bidder1, 100 ether, 15 ether, permit);

    // But a smaller bid should work
    permitter.validateBid(bidder1, 50 ether, 10 ether, permit);

    assertEq(permitter.getTotalEthRaised(), 50 ether);
  }

  function test_OwnerAdjustsCapsHigherDuringAuction() public {
    uint256 expiry = block.timestamp + 24 hours;
    bytes memory permit = _createPermitSignature(bidder1, MAX_TOKENS_PER_BIDDER, expiry);

    // Set a low initial cap
    vm.prank(auctionOwner);
    permitter.updateMaxTotalEth(10 ether);

    // Place bids up to the cap
    permitter.validateBid(bidder1, 100 ether, 10 ether, permit);

    // Next bid fails
    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.ExceedsTotalCap.selector, 1 ether, 10 ether, 10 ether)
    );
    permitter.validateBid(bidder1, 10 ether, 1 ether, permit);

    // Owner raises the cap
    vm.prank(auctionOwner);
    permitter.updateMaxTotalEth(100 ether);

    // Now the bid succeeds
    permitter.validateBid(bidder1, 100 ether, 10 ether, permit);

    assertEq(permitter.getTotalEthRaised(), 20 ether);
  }
}

/// @notice Test permit expiry scenarios.
contract PermitExpiry is IntegrationTest {
  function test_PermitExpiresAfterTimestamp() public {
    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permit = _createPermitSignature(bidder1, MAX_TOKENS_PER_BIDDER, expiry);

    // Bid succeeds before expiry
    permitter.validateBid(bidder1, 100 ether, 1 ether, permit);

    // Warp past expiry
    vm.warp(expiry + 1);

    // Bid fails after expiry
    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.SignatureExpired.selector, expiry, block.timestamp)
    );
    permitter.validateBid(bidder1, 100 ether, 1 ether, permit);
  }

  function test_BidderCanGetNewPermitAfterExpiry() public {
    uint256 expiry1 = block.timestamp + 1 hours;
    bytes memory permit1 = _createPermitSignature(bidder1, MAX_TOKENS_PER_BIDDER, expiry1);

    // Use first permit
    permitter.validateBid(bidder1, 100 ether, 1 ether, permit1);

    // Warp past first expiry
    vm.warp(expiry1 + 1);

    // First permit is now expired
    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.SignatureExpired.selector, expiry1, block.timestamp)
    );
    permitter.validateBid(bidder1, 100 ether, 1 ether, permit1);

    // Get a new permit with new expiry
    uint256 expiry2 = block.timestamp + 24 hours;
    bytes memory permit2 = _createPermitSignature(bidder1, MAX_TOKENS_PER_BIDDER, expiry2);

    // New permit works
    permitter.validateBid(bidder1, 100 ether, 1 ether, permit2);

    assertEq(permitter.getBidAmount(bidder1), 200 ether);
  }
}

/// @notice Test multiple auctions scenario.
contract MultipleAuctions is IntegrationTest {
  Permitter public permitter2;
  Permitter public permitter3;

  function setUp() public override {
    super.setUp();

    // Deploy additional permitters for different auctions
    vm.startPrank(deployer);
    address permitter2Address = factory.createPermitter(
      trustedSigner, 50 ether, 500 ether, auctionOwner, bytes32(uint256(2))
    );
    address permitter3Address = factory.createPermitter(
      trustedSigner, 200 ether, 2000 ether, auctionOwner, bytes32(uint256(3))
    );
    vm.stopPrank();

    permitter2 = Permitter(permitter2Address);
    permitter3 = Permitter(permitter3Address);
  }

  function test_BidderParticipatesInMultipleAuctions() public {
    uint256 expiry = block.timestamp + 24 hours;

    // Create permits for each auction (each has its own domain separator)
    bytes memory permit1 = _createPermitSignatureForPermitter(bidder1, 400 ether, expiry, permitter);
    bytes memory permit2 =
      _createPermitSignatureForPermitter(bidder1, 300 ether, expiry, permitter2);
    bytes memory permit3 =
      _createPermitSignatureForPermitter(bidder1, 1000 ether, expiry, permitter3);

    // Bid in all auctions
    permitter.validateBid(bidder1, 100 ether, 10 ether, permit1);
    permitter2.validateBid(bidder1, 200 ether, 20 ether, permit2);
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
    bytes memory permit1 =
      _createPermitSignatureForPermitter(bidder1, MAX_TOKENS_PER_BIDDER, expiry, permitter);

    // Try to use it in auction 2 - should fail because domain separator is different
    vm.expectRevert();
    permitter2.validateBid(bidder1, 100 ether, 10 ether, permit1);
  }

  function _createPermitSignatureForPermitter(
    address _bidder,
    uint256 _maxBidAmount,
    uint256 _expiry,
    Permitter _permitter
  ) internal view returns (bytes memory permitData) {
    IPermitter.Permit memory permit = IPermitter.Permit({
      bidder: _bidder, maxBidAmount: _maxBidAmount, expiry: _expiry
    });

    bytes32 structHash =
      keccak256(abi.encode(PERMIT_TYPEHASH, permit.bidder, permit.maxBidAmount, permit.expiry));

    bytes32 domainSeparator = _permitter.domainSeparator();
    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
    bytes memory signature = abi.encodePacked(r, s, v);

    permitData = abi.encode(permit, signature);
  }
}
