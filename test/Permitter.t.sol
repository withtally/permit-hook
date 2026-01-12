// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {Permitter} from "src/Permitter.sol";
import {IPermitter} from "src/interfaces/IPermitter.sol";

/// @notice Base test contract for Permitter tests.
contract PermitterTest is Test {
  Permitter public permitter;

  // Test accounts
  address public owner = makeAddr("owner");
  address public trustedSigner;
  uint256 public signerPrivateKey;
  address public bidder = makeAddr("bidder");
  address public otherBidder = makeAddr("otherBidder");
  address public authorizedCaller = makeAddr("authorizedCaller");

  // Default configuration
  uint256 public constant MAX_TOTAL_ETH = 100 ether;
  uint256 public constant MAX_TOKENS_PER_BIDDER = 1000 ether;
  uint256 public constant MIN_TOKENS_PER_BIDDER = 10 ether;

  // EIP-712 constants
  bytes32 public constant PERMIT_TYPEHASH = keccak256("Permit(address bidder,uint256 expiry)");

  function setUp() public virtual {
    // Create a trusted signer with a known private key
    signerPrivateKey = 0x1234;
    trustedSigner = vm.addr(signerPrivateKey);

    // Deploy the Permitter with authorized caller
    permitter = new Permitter(
      trustedSigner,
      MAX_TOTAL_ETH,
      MAX_TOKENS_PER_BIDDER,
      MIN_TOKENS_PER_BIDDER,
      owner,
      authorizedCaller
    );
  }

  /// @notice Helper function to create a valid permit signature.
  function _createPermitSignature(address _bidder, uint256 _expiry)
    internal
    view
    returns (bytes memory permitData)
  {
    return _createPermitSignatureWithKey(_bidder, _expiry, signerPrivateKey);
  }

  /// @notice Helper function to create a permit signature with a specific private key.
  function _createPermitSignatureWithKey(address _bidder, uint256 _expiry, uint256 _privateKey)
    internal
    view
    returns (bytes memory permitData)
  {
    IPermitter.Permit memory permit = IPermitter.Permit({bidder: _bidder, expiry: _expiry});

    bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, permit.bidder, permit.expiry));

    bytes32 domainSeparator = permitter.domainSeparator();
    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(_privateKey, digest);
    bytes memory signature = abi.encodePacked(r, s, v);

    permitData = abi.encode(permit, signature);
  }
}

/// @notice Tests for constructor behavior.
contract Constructor is PermitterTest {
  function test_SetsInitialState() public view {
    assertEq(permitter.trustedSigner(), trustedSigner);
    assertEq(permitter.maxTotalEth(), MAX_TOTAL_ETH);
    assertEq(permitter.maxTokensPerBidder(), MAX_TOKENS_PER_BIDDER);
    assertEq(permitter.minTokensPerBidder(), MIN_TOKENS_PER_BIDDER);
    assertEq(permitter.owner(), owner);
    assertEq(permitter.paused(), false);
    assertEq(permitter.totalEthRaised(), 0);
    assertEq(permitter.authorizedCaller(), authorizedCaller);
  }

  function test_RevertIf_TrustedSignerIsZero() public {
    vm.expectRevert(IPermitter.InvalidTrustedSigner.selector);
    new Permitter(
      address(0),
      MAX_TOTAL_ETH,
      MAX_TOKENS_PER_BIDDER,
      MIN_TOKENS_PER_BIDDER,
      owner,
      authorizedCaller
    );
  }

  function test_RevertIf_OwnerIsZero() public {
    vm.expectRevert(IPermitter.InvalidOwner.selector);
    new Permitter(
      trustedSigner,
      MAX_TOTAL_ETH,
      MAX_TOKENS_PER_BIDDER,
      MIN_TOKENS_PER_BIDDER,
      address(0),
      authorizedCaller
    );
  }

  function test_RevertIf_MaxTotalEthIsZero() public {
    vm.expectRevert(IPermitter.InvalidCap.selector);
    new Permitter(
      trustedSigner, 0, MAX_TOKENS_PER_BIDDER, MIN_TOKENS_PER_BIDDER, owner, authorizedCaller
    );
  }

  function test_RevertIf_MaxTokensPerBidderIsZero() public {
    vm.expectRevert(IPermitter.InvalidCap.selector);
    new Permitter(trustedSigner, MAX_TOTAL_ETH, 0, MIN_TOKENS_PER_BIDDER, owner, authorizedCaller);
  }

  function test_AllowsZeroMinTokensPerBidder() public {
    // minTokensPerBidder can be 0 (no minimum requirement)
    Permitter p =
      new Permitter(trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, 0, owner, authorizedCaller);
    assertEq(p.minTokensPerBidder(), 0);
  }

  function test_RevertIf_MinTokensExceedsMaxTokens() public {
    uint256 minTokens = 2000 ether;
    uint256 maxTokens = 1000 ether;
    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.MinTokensExceedsMaxTokens.selector, minTokens, maxTokens)
    );
    new Permitter(trustedSigner, MAX_TOTAL_ETH, maxTokens, minTokens, owner, authorizedCaller);
  }

  function test_AllowsMinTokensEqualToMaxTokens() public {
    uint256 equalTokens = 500 ether;
    Permitter p =
      new Permitter(trustedSigner, MAX_TOTAL_ETH, equalTokens, equalTokens, owner, authorizedCaller);
    assertEq(p.minTokensPerBidder(), equalTokens);
    assertEq(p.maxTokensPerBidder(), equalTokens);
  }
}

/// @notice Tests for validateBid with valid permits.
contract ValidateBidSuccess is PermitterTest {
  function test_ValidBidSucceeds() public {
    uint256 bidAmount = 100 ether;
    uint256 ethValue = 1 ether;
    uint256 expiry = block.timestamp + 1 hours;

    bytes memory permitData = _createPermitSignature(bidder, expiry);

    vm.prank(authorizedCaller);
    bool result = permitter.validateBid(bidder, bidAmount, ethValue, permitData);

    assertTrue(result);
    assertEq(permitter.getBidAmount(bidder), bidAmount);
    assertEq(permitter.getTotalEthRaised(), ethValue);
  }

  function test_MultipleBidsFromSameBidder() public {
    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permitData = _createPermitSignature(bidder, expiry);

    // First bid
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder, 100 ether, 1 ether, permitData);
    assertEq(permitter.getBidAmount(bidder), 100 ether);

    // Second bid
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder, 200 ether, 2 ether, permitData);
    assertEq(permitter.getBidAmount(bidder), 300 ether);

    // Third bid
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder, 50 ether, 0.5 ether, permitData);
    assertEq(permitter.getBidAmount(bidder), 350 ether);
    assertEq(permitter.getTotalEthRaised(), 3.5 ether);
  }

  function test_DifferentBiddersCanBid() public {
    uint256 expiry = block.timestamp + 1 hours;

    bytes memory permitData1 = _createPermitSignature(bidder, expiry);
    bytes memory permitData2 = _createPermitSignature(otherBidder, expiry);

    vm.prank(authorizedCaller);
    permitter.validateBid(bidder, 100 ether, 1 ether, permitData1);
    vm.prank(authorizedCaller);
    permitter.validateBid(otherBidder, 200 ether, 2 ether, permitData2);

    assertEq(permitter.getBidAmount(bidder), 100 ether);
    assertEq(permitter.getBidAmount(otherBidder), 200 ether);
    assertEq(permitter.getTotalEthRaised(), 3 ether);
  }

  function test_EmitsPermitVerifiedEvent() public {
    uint256 bidAmount = 100 ether;
    uint256 ethValue = 1 ether;
    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permitData = _createPermitSignature(bidder, expiry);

    vm.expectEmit(true, false, false, true);
    emit IPermitter.PermitVerified(
      bidder, bidAmount, MAX_TOKENS_PER_BIDDER - bidAmount, MAX_TOTAL_ETH - ethValue
    );

    vm.prank(authorizedCaller);
    permitter.validateBid(bidder, bidAmount, ethValue, permitData);
  }
}

/// @notice Tests for validateBid reverts.
contract ValidateBidRevert is PermitterTest {
  function test_RevertIf_CallerNotAuthorized() public {
    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permitData = _createPermitSignature(bidder, expiry);

    // Try to call from non-authorized address
    vm.expectRevert(IPermitter.UnauthorizedCaller.selector);
    permitter.validateBid(bidder, 100 ether, 1 ether, permitData);
  }

  function test_RevertIf_Paused() public {
    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permitData = _createPermitSignature(bidder, expiry);

    vm.prank(owner);
    permitter.pause();

    vm.expectRevert(IPermitter.ContractPaused.selector);
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder, 100 ether, 1 ether, permitData);
  }

  function test_RevertIf_BidBelowMinimum() public {
    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permitData = _createPermitSignature(bidder, expiry);

    // Try to bid less than minimum (MIN_TOKENS_PER_BIDDER = 10 ether)
    uint256 lowBid = 5 ether;
    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.BidBelowMinimum.selector, lowBid, MIN_TOKENS_PER_BIDDER)
    );
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder, lowBid, 0.05 ether, permitData);
  }

  function test_RevertIf_SignatureExpired() public {
    uint256 expiry = block.timestamp - 1; // Already expired
    bytes memory permitData = _createPermitSignature(bidder, expiry);

    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.SignatureExpired.selector, expiry, block.timestamp)
    );
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder, 100 ether, 1 ether, permitData);
  }

  function test_RevertIf_SignatureFromWrongSigner() public {
    uint256 wrongSignerKey = 0x5678;
    address wrongSigner = vm.addr(wrongSignerKey);
    uint256 expiry = block.timestamp + 1 hours;

    bytes memory permitData = _createPermitSignatureWithKey(bidder, expiry, wrongSignerKey);

    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.InvalidSignature.selector, trustedSigner, wrongSigner)
    );
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder, 100 ether, 1 ether, permitData);
  }

  function test_RevertIf_BidderMismatch() public {
    uint256 expiry = block.timestamp + 1 hours;
    // Create permit for otherBidder but try to use it for bidder
    bytes memory permitData = _createPermitSignature(otherBidder, expiry);

    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.InvalidSignature.selector, bidder, otherBidder)
    );
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder, 100 ether, 1 ether, permitData);
  }

  function test_RevertIf_ExceedsMaxTokensPerBidder() public {
    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permitData = _createPermitSignature(bidder, expiry);

    // First bid that brings us close to the cap
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder, 900 ether, 9 ether, permitData);

    // Second bid that exceeds maxTokensPerBidder (1000 ether)
    vm.expectRevert(
      abi.encodeWithSelector(
        IPermitter.ExceedsPersonalCap.selector,
        200 ether, // requested
        MAX_TOKENS_PER_BIDDER, // cap
        900 ether // already bid
      )
    );
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder, 200 ether, 2 ether, permitData);
  }

  function test_RevertIf_ExceedsTotalEthCap() public {
    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permitData = _createPermitSignature(bidder, expiry);

    // Bid that brings us close to the cap
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder, 100 ether, 99 ether, permitData);

    // Bid that exceeds total cap
    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.ExceedsTotalCap.selector, 2 ether, MAX_TOTAL_ETH, 99 ether)
    );
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder, 100 ether, 2 ether, permitData);
  }
}

/// @notice Tests for minimum bid enforcement.
contract MinTokensPerBidderTests is PermitterTest {
  function test_BidAtExactMinimumSucceeds() public {
    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permitData = _createPermitSignature(bidder, expiry);

    vm.prank(authorizedCaller);
    bool result = permitter.validateBid(bidder, MIN_TOKENS_PER_BIDDER, 0.1 ether, permitData);

    assertTrue(result);
    assertEq(permitter.getBidAmount(bidder), MIN_TOKENS_PER_BIDDER);
  }

  function test_BidAboveMinimumSucceeds() public {
    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permitData = _createPermitSignature(bidder, expiry);

    uint256 aboveMinBid = MIN_TOKENS_PER_BIDDER + 1 ether;
    vm.prank(authorizedCaller);
    bool result = permitter.validateBid(bidder, aboveMinBid, 0.11 ether, permitData);

    assertTrue(result);
    assertEq(permitter.getBidAmount(bidder), aboveMinBid);
  }

  function test_ZeroMinTokensPerBidderAllowsAnyBid() public {
    // Deploy a new permitter with zero minimum
    Permitter zeroMinPermitter =
      new Permitter(trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, 0, owner, authorizedCaller);

    uint256 expiry = block.timestamp + 1 hours;
    IPermitter.Permit memory permit = IPermitter.Permit({bidder: bidder, expiry: expiry});
    bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, permit.bidder, permit.expiry));
    bytes32 domainSeparator = zeroMinPermitter.domainSeparator();
    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
    bytes memory signature = abi.encodePacked(r, s, v);
    bytes memory permitData = abi.encode(permit, signature);

    // Even a 1 wei bid should work
    vm.prank(authorizedCaller);
    bool result = zeroMinPermitter.validateBid(bidder, 1, 1, permitData);

    assertTrue(result);
    assertEq(zeroMinPermitter.getBidAmount(bidder), 1);
  }
}

/// @notice Tests for timelock-based cap updates.
contract TimelockCapUpdates is PermitterTest {
  function test_ScheduleUpdateMaxTotalEth() public {
    uint256 newCap = 200 ether;
    uint256 expectedExecuteTime = block.timestamp + permitter.UPDATE_DELAY();

    vm.expectEmit(true, false, false, true);
    emit IPermitter.CapUpdateScheduled(IPermitter.CapType.TOTAL_ETH, newCap, expectedExecuteTime);

    vm.prank(owner);
    permitter.scheduleUpdateMaxTotalEth(newCap);

    assertEq(permitter.pendingMaxTotalEth(), newCap);
    assertEq(permitter.pendingMaxTotalEthTime(), expectedExecuteTime);
    // Original cap unchanged
    assertEq(permitter.maxTotalEth(), MAX_TOTAL_ETH);
  }

  function test_RevertIf_ScheduleUpdateMaxTotalEthWithZero() public {
    vm.expectRevert(IPermitter.InvalidCap.selector);
    vm.prank(owner);
    permitter.scheduleUpdateMaxTotalEth(0);
  }

  function test_RevertIf_ExecuteUpdateMaxTotalEthTooEarly() public {
    uint256 newCap = 200 ether;

    vm.prank(owner);
    permitter.scheduleUpdateMaxTotalEth(newCap);

    // Try to execute immediately
    uint256 scheduledTime = permitter.pendingMaxTotalEthTime();
    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.UpdateTooEarly.selector, scheduledTime, block.timestamp)
    );
    vm.prank(owner);
    permitter.executeUpdateMaxTotalEth();
  }

  function test_RevertIf_ExecuteUpdateMaxTotalEthNotScheduled() public {
    vm.expectRevert(IPermitter.UpdateNotScheduled.selector);
    vm.prank(owner);
    permitter.executeUpdateMaxTotalEth();
  }

  function test_ExecuteUpdateMaxTotalEth_AfterDelay() public {
    uint256 newCap = 200 ether;

    vm.prank(owner);
    permitter.scheduleUpdateMaxTotalEth(newCap);

    // Fast forward past the delay
    vm.warp(block.timestamp + permitter.UPDATE_DELAY());

    vm.expectEmit(true, false, false, true);
    emit IPermitter.CapUpdated(IPermitter.CapType.TOTAL_ETH, MAX_TOTAL_ETH, newCap);

    vm.prank(owner);
    permitter.executeUpdateMaxTotalEth();

    assertEq(permitter.maxTotalEth(), newCap);
    assertEq(permitter.pendingMaxTotalEth(), 0);
    assertEq(permitter.pendingMaxTotalEthTime(), 0);
  }

  function test_RevertIf_NewCapBelowTotalRaised() public {
    // First, raise some ETH
    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permitData = _createPermitSignature(bidder, expiry);

    vm.prank(authorizedCaller);
    permitter.validateBid(bidder, 100 ether, 50 ether, permitData);

    // Try to schedule a cap below what's already raised
    uint256 newCap = 30 ether;
    vm.prank(owner);
    permitter.scheduleUpdateMaxTotalEth(newCap);

    // Fast forward
    vm.warp(block.timestamp + permitter.UPDATE_DELAY());

    // Should revert because cap is below totalEthRaised
    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.CapBelowCurrentAmount.selector, newCap, 50 ether)
    );
    vm.prank(owner);
    permitter.executeUpdateMaxTotalEth();
  }

  function test_ScheduleUpdateMaxTokensPerBidder() public {
    uint256 newCap = 2000 ether;
    uint256 expectedExecuteTime = block.timestamp + permitter.UPDATE_DELAY();

    vm.expectEmit(true, false, false, true);
    emit IPermitter.CapUpdateScheduled(
      IPermitter.CapType.TOKENS_PER_BIDDER, newCap, expectedExecuteTime
    );

    vm.prank(owner);
    permitter.scheduleUpdateMaxTokensPerBidder(newCap);

    assertEq(permitter.pendingMaxTokensPerBidder(), newCap);
    assertEq(permitter.pendingMaxTokensPerBidderTime(), expectedExecuteTime);
  }

  function test_ExecuteUpdateMaxTokensPerBidder_AfterDelay() public {
    uint256 newCap = 2000 ether;

    vm.prank(owner);
    permitter.scheduleUpdateMaxTokensPerBidder(newCap);

    vm.warp(block.timestamp + permitter.UPDATE_DELAY());

    vm.expectEmit(true, false, false, true);
    emit IPermitter.CapUpdated(IPermitter.CapType.TOKENS_PER_BIDDER, MAX_TOKENS_PER_BIDDER, newCap);

    vm.prank(owner);
    permitter.executeUpdateMaxTokensPerBidder();

    assertEq(permitter.maxTokensPerBidder(), newCap);
  }
}

/// @notice Tests for timelock-based signer updates.
contract TimelockSignerUpdates is PermitterTest {
  function test_ScheduleUpdateTrustedSigner() public {
    address newSigner = makeAddr("newSigner");
    uint256 expectedExecuteTime = block.timestamp + permitter.UPDATE_DELAY();

    vm.expectEmit(true, false, false, true);
    emit IPermitter.SignerUpdateScheduled(newSigner, expectedExecuteTime);

    vm.prank(owner);
    permitter.scheduleUpdateTrustedSigner(newSigner);

    assertEq(permitter.pendingTrustedSigner(), newSigner);
    assertEq(permitter.pendingTrustedSignerTime(), expectedExecuteTime);
    // Original signer unchanged
    assertEq(permitter.trustedSigner(), trustedSigner);
  }

  function test_RevertIf_ScheduleUpdateTrustedSignerWithZero() public {
    vm.expectRevert(IPermitter.InvalidTrustedSigner.selector);
    vm.prank(owner);
    permitter.scheduleUpdateTrustedSigner(address(0));
  }

  function test_RevertIf_ExecuteUpdateTrustedSignerTooEarly() public {
    address newSigner = makeAddr("newSigner");

    vm.prank(owner);
    permitter.scheduleUpdateTrustedSigner(newSigner);

    uint256 scheduledTime = permitter.pendingTrustedSignerTime();
    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.UpdateTooEarly.selector, scheduledTime, block.timestamp)
    );
    vm.prank(owner);
    permitter.executeUpdateTrustedSigner();
  }

  function test_ExecuteUpdateTrustedSigner_AfterDelay() public {
    address newSigner = makeAddr("newSigner");

    vm.prank(owner);
    permitter.scheduleUpdateTrustedSigner(newSigner);

    vm.warp(block.timestamp + permitter.UPDATE_DELAY());

    vm.expectEmit(true, true, false, false);
    emit IPermitter.SignerUpdated(trustedSigner, newSigner);

    vm.prank(owner);
    permitter.executeUpdateTrustedSigner();

    assertEq(permitter.trustedSigner(), newSigner);
    assertEq(permitter.pendingTrustedSigner(), address(0));
    assertEq(permitter.pendingTrustedSignerTime(), 0);
  }

  function test_OldSignerInvalidAfterRotation() public {
    uint256 expiry = block.timestamp + 2 hours;

    // Create a permit with the old signer
    bytes memory oldPermitData = _createPermitSignature(bidder, expiry);

    // Schedule rotation to new signer
    uint256 newSignerKey = 0x5678;
    address newSigner = vm.addr(newSignerKey);
    vm.prank(owner);
    permitter.scheduleUpdateTrustedSigner(newSigner);

    // Fast forward and execute
    vm.warp(block.timestamp + permitter.UPDATE_DELAY());
    vm.prank(owner);
    permitter.executeUpdateTrustedSigner();

    // Old permit should fail
    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.InvalidSignature.selector, newSigner, trustedSigner)
    );
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder, 100 ether, 1 ether, oldPermitData);
  }

  function test_NewSignerWorksAfterRotation() public {
    uint256 newSignerKey = 0x5678;
    address newSigner = vm.addr(newSignerKey);

    // Schedule rotation
    vm.prank(owner);
    permitter.scheduleUpdateTrustedSigner(newSigner);

    // Fast forward and execute
    vm.warp(block.timestamp + permitter.UPDATE_DELAY());
    vm.prank(owner);
    permitter.executeUpdateTrustedSigner();

    // Create a permit with the new signer
    uint256 expiry = block.timestamp + 1 hours;
    bytes memory newPermitData = _createPermitSignatureWithKey(bidder, expiry, newSignerKey);

    // New permit should work
    vm.prank(authorizedCaller);
    bool result = permitter.validateBid(bidder, 100 ether, 1 ether, newPermitData);
    assertTrue(result);
  }
}

/// @notice Tests for authorized caller management.
contract AuthorizedCallerTests is PermitterTest {
  function test_UpdateAuthorizedCaller() public {
    address newCaller = makeAddr("newCaller");

    vm.expectEmit(true, true, false, false);
    emit IPermitter.AuthorizedCallerUpdated(authorizedCaller, newCaller);

    vm.prank(owner);
    permitter.updateAuthorizedCaller(newCaller);

    assertEq(permitter.authorizedCaller(), newCaller);
  }

  function test_RevertIf_UpdateAuthorizedCallerByNonOwner() public {
    vm.expectRevert(IPermitter.Unauthorized.selector);
    vm.prank(bidder);
    permitter.updateAuthorizedCaller(makeAddr("newCaller"));
  }

  function test_NewCallerCanValidateBid() public {
    address newCaller = makeAddr("newCaller");

    vm.prank(owner);
    permitter.updateAuthorizedCaller(newCaller);

    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permitData = _createPermitSignature(bidder, expiry);

    // New caller can validate
    vm.prank(newCaller);
    bool result = permitter.validateBid(bidder, 100 ether, 1 ether, permitData);
    assertTrue(result);

    // Old caller cannot validate
    vm.expectRevert(IPermitter.UnauthorizedCaller.selector);
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder, 100 ether, 1 ether, permitData);
  }

  function test_CanSetAuthorizedCallerToZero() public {
    // Setting to zero disables all validateBid calls
    vm.prank(owner);
    permitter.updateAuthorizedCaller(address(0));

    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permitData = _createPermitSignature(bidder, expiry);

    // Any caller will fail
    vm.expectRevert(IPermitter.UnauthorizedCaller.selector);
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder, 100 ether, 1 ether, permitData);
  }
}

/// @notice Tests for pause/unpause functionality.
contract PauseTests is PermitterTest {
  function test_Pause() public {
    vm.expectEmit(true, false, false, false);
    emit IPermitter.Paused(owner);

    vm.prank(owner);
    permitter.pause();

    assertTrue(permitter.paused());
  }

  function test_RevertIf_PauseCalledByNonOwner() public {
    vm.expectRevert(IPermitter.Unauthorized.selector);
    vm.prank(bidder);
    permitter.pause();
  }

  function test_Unpause() public {
    vm.prank(owner);
    permitter.pause();

    vm.expectEmit(true, false, false, false);
    emit IPermitter.Unpaused(owner);

    vm.prank(owner);
    permitter.unpause();

    assertFalse(permitter.paused());
  }

  function test_RevertIf_UnpauseCalledByNonOwner() public {
    vm.prank(owner);
    permitter.pause();

    vm.expectRevert(IPermitter.Unauthorized.selector);
    vm.prank(bidder);
    permitter.unpause();
  }
}

/// @notice Tests for view functions.
contract ViewFunctions is PermitterTest {
  function test_GetBidAmount() public {
    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permitData = _createPermitSignature(bidder, expiry);

    assertEq(permitter.getBidAmount(bidder), 0);

    vm.prank(authorizedCaller);
    permitter.validateBid(bidder, 100 ether, 1 ether, permitData);
    assertEq(permitter.getBidAmount(bidder), 100 ether);

    vm.prank(authorizedCaller);
    permitter.validateBid(bidder, 50 ether, 0.5 ether, permitData);
    assertEq(permitter.getBidAmount(bidder), 150 ether);
  }

  function test_GetTotalEthRaised() public {
    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permitData1 = _createPermitSignature(bidder, expiry);
    bytes memory permitData2 = _createPermitSignature(otherBidder, expiry);

    assertEq(permitter.getTotalEthRaised(), 0);

    vm.prank(authorizedCaller);
    permitter.validateBid(bidder, 100 ether, 5 ether, permitData1);
    assertEq(permitter.getTotalEthRaised(), 5 ether);

    vm.prank(authorizedCaller);
    permitter.validateBid(otherBidder, 200 ether, 10 ether, permitData2);
    assertEq(permitter.getTotalEthRaised(), 15 ether);
  }

  function test_DomainSeparator() public view {
    bytes32 domainSeparator = permitter.domainSeparator();
    // Just verify it returns a non-zero value (actual value depends on contract address and chain)
    assertTrue(domainSeparator != bytes32(0));
  }

  function test_UPDATE_DELAY() public view {
    assertEq(permitter.UPDATE_DELAY(), 1 hours);
  }
}
