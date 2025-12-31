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

  // Default configuration
  uint256 public constant MAX_TOTAL_ETH = 100 ether;
  uint256 public constant MAX_TOKENS_PER_BIDDER = 1000 ether;

  // EIP-712 constants
  bytes32 public constant PERMIT_TYPEHASH =
    keccak256("Permit(address bidder,uint256 maxBidAmount,uint256 expiry)");

  function setUp() public virtual {
    // Create a trusted signer with a known private key
    signerPrivateKey = 0x1234;
    trustedSigner = vm.addr(signerPrivateKey);

    // Deploy the Permitter
    permitter = new Permitter(trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner);
  }

  /// @notice Helper function to create a valid permit signature.
  function _createPermitSignature(address _bidder, uint256 _maxBidAmount, uint256 _expiry)
    internal
    view
    returns (bytes memory permitData)
  {
    return _createPermitSignatureWithKey(_bidder, _maxBidAmount, _expiry, signerPrivateKey);
  }

  /// @notice Helper function to create a permit signature with a specific private key.
  function _createPermitSignatureWithKey(
    address _bidder,
    uint256 _maxBidAmount,
    uint256 _expiry,
    uint256 _privateKey
  ) internal view returns (bytes memory permitData) {
    IPermitter.Permit memory permit = IPermitter.Permit({
      bidder: _bidder, maxBidAmount: _maxBidAmount, expiry: _expiry
    });

    bytes32 structHash =
      keccak256(abi.encode(PERMIT_TYPEHASH, permit.bidder, permit.maxBidAmount, permit.expiry));

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
    assertEq(permitter.owner(), owner);
    assertEq(permitter.paused(), false);
    assertEq(permitter.totalEthRaised(), 0);
  }

  function test_RevertIf_TrustedSignerIsZero() public {
    vm.expectRevert(IPermitter.InvalidTrustedSigner.selector);
    new Permitter(address(0), MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner);
  }

  function test_RevertIf_OwnerIsZero() public {
    vm.expectRevert(IPermitter.InvalidOwner.selector);
    new Permitter(trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, address(0));
  }
}

/// @notice Tests for validateBid with valid permits.
contract ValidateBidSuccess is PermitterTest {
  function test_ValidBidSucceeds() public {
    uint256 bidAmount = 100 ether;
    uint256 ethValue = 1 ether;
    uint256 expiry = block.timestamp + 1 hours;

    bytes memory permitData = _createPermitSignature(bidder, MAX_TOKENS_PER_BIDDER, expiry);

    bool result = permitter.validateBid(bidder, bidAmount, ethValue, permitData);

    assertTrue(result);
    assertEq(permitter.getBidAmount(bidder), bidAmount);
    assertEq(permitter.getTotalEthRaised(), ethValue);
  }

  function test_MultipleBidsFromSameBidder() public {
    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permitData = _createPermitSignature(bidder, MAX_TOKENS_PER_BIDDER, expiry);

    // First bid
    permitter.validateBid(bidder, 100 ether, 1 ether, permitData);
    assertEq(permitter.getBidAmount(bidder), 100 ether);

    // Second bid
    permitter.validateBid(bidder, 200 ether, 2 ether, permitData);
    assertEq(permitter.getBidAmount(bidder), 300 ether);

    // Third bid
    permitter.validateBid(bidder, 50 ether, 0.5 ether, permitData);
    assertEq(permitter.getBidAmount(bidder), 350 ether);
    assertEq(permitter.getTotalEthRaised(), 3.5 ether);
  }

  function test_DifferentBiddersCanBid() public {
    uint256 expiry = block.timestamp + 1 hours;

    bytes memory permitData1 = _createPermitSignature(bidder, MAX_TOKENS_PER_BIDDER, expiry);
    bytes memory permitData2 = _createPermitSignature(otherBidder, MAX_TOKENS_PER_BIDDER, expiry);

    permitter.validateBid(bidder, 100 ether, 1 ether, permitData1);
    permitter.validateBid(otherBidder, 200 ether, 2 ether, permitData2);

    assertEq(permitter.getBidAmount(bidder), 100 ether);
    assertEq(permitter.getBidAmount(otherBidder), 200 ether);
    assertEq(permitter.getTotalEthRaised(), 3 ether);
  }

  function test_EmitsPermitVerifiedEvent() public {
    uint256 bidAmount = 100 ether;
    uint256 ethValue = 1 ether;
    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permitData = _createPermitSignature(bidder, MAX_TOKENS_PER_BIDDER, expiry);

    vm.expectEmit(true, false, false, true);
    emit IPermitter.PermitVerified(
      bidder, bidAmount, MAX_TOKENS_PER_BIDDER - bidAmount, MAX_TOTAL_ETH - ethValue
    );

    permitter.validateBid(bidder, bidAmount, ethValue, permitData);
  }
}

/// @notice Tests for validateBid reverts.
contract ValidateBidRevert is PermitterTest {
  function test_RevertIf_Paused() public {
    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permitData = _createPermitSignature(bidder, MAX_TOKENS_PER_BIDDER, expiry);

    vm.prank(owner);
    permitter.pause();

    vm.expectRevert(IPermitter.ContractPaused.selector);
    permitter.validateBid(bidder, 100 ether, 1 ether, permitData);
  }

  function test_RevertIf_SignatureExpired() public {
    uint256 expiry = block.timestamp - 1; // Already expired
    bytes memory permitData = _createPermitSignature(bidder, MAX_TOKENS_PER_BIDDER, expiry);

    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.SignatureExpired.selector, expiry, block.timestamp)
    );
    permitter.validateBid(bidder, 100 ether, 1 ether, permitData);
  }

  function test_RevertIf_SignatureFromWrongSigner() public {
    uint256 wrongSignerKey = 0x5678;
    address wrongSigner = vm.addr(wrongSignerKey);
    uint256 expiry = block.timestamp + 1 hours;

    bytes memory permitData =
      _createPermitSignatureWithKey(bidder, MAX_TOKENS_PER_BIDDER, expiry, wrongSignerKey);

    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.InvalidSignature.selector, trustedSigner, wrongSigner)
    );
    permitter.validateBid(bidder, 100 ether, 1 ether, permitData);
  }

  function test_RevertIf_BidderMismatch() public {
    uint256 expiry = block.timestamp + 1 hours;
    // Create permit for otherBidder but try to use it for bidder
    bytes memory permitData = _createPermitSignature(otherBidder, MAX_TOKENS_PER_BIDDER, expiry);

    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.InvalidSignature.selector, bidder, otherBidder)
    );
    permitter.validateBid(bidder, 100 ether, 1 ether, permitData);
  }

  function test_RevertIf_ExceedsPermitMaxBidAmount() public {
    uint256 permitMax = 500 ether;
    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permitData = _createPermitSignature(bidder, permitMax, expiry);

    // First bid succeeds
    permitter.validateBid(bidder, 400 ether, 4 ether, permitData);

    // Second bid exceeds permit max
    vm.expectRevert(
      abi.encodeWithSelector(
        IPermitter.ExceedsPersonalCap.selector, 200 ether, permitMax, 400 ether
      )
    );
    permitter.validateBid(bidder, 200 ether, 2 ether, permitData);
  }

  function test_RevertIf_ExceedsGlobalMaxTokensPerBidder() public {
    // Set a lower global cap than the permit allows
    vm.prank(owner);
    permitter.updateMaxTokensPerBidder(300 ether);

    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permitData = _createPermitSignature(bidder, 500 ether, expiry);

    // First bid succeeds
    permitter.validateBid(bidder, 200 ether, 2 ether, permitData);

    // Second bid exceeds global max
    vm.expectRevert(
      abi.encodeWithSelector(
        IPermitter.ExceedsPersonalCap.selector, 200 ether, 300 ether, 200 ether
      )
    );
    permitter.validateBid(bidder, 200 ether, 2 ether, permitData);
  }

  function test_RevertIf_ExceedsTotalEthCap() public {
    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permitData = _createPermitSignature(bidder, MAX_TOKENS_PER_BIDDER, expiry);

    // Bid that brings us close to the cap
    permitter.validateBid(bidder, 100 ether, 99 ether, permitData);

    // Bid that exceeds total cap
    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.ExceedsTotalCap.selector, 2 ether, MAX_TOTAL_ETH, 99 ether)
    );
    permitter.validateBid(bidder, 10 ether, 2 ether, permitData);
  }
}

/// @notice Tests for owner-only functions.
contract OwnerFunctions is PermitterTest {
  function test_UpdateMaxTotalEth() public {
    uint256 newCap = 200 ether;

    vm.expectEmit(true, false, false, true);
    emit IPermitter.CapUpdated(IPermitter.CapType.TOTAL_ETH, MAX_TOTAL_ETH, newCap);

    vm.prank(owner);
    permitter.updateMaxTotalEth(newCap);

    assertEq(permitter.maxTotalEth(), newCap);
  }

  function test_RevertIf_UpdateMaxTotalEthCalledByNonOwner() public {
    vm.expectRevert(IPermitter.Unauthorized.selector);
    vm.prank(bidder);
    permitter.updateMaxTotalEth(200 ether);
  }

  function test_UpdateMaxTokensPerBidder() public {
    uint256 newCap = 2000 ether;

    vm.expectEmit(true, false, false, true);
    emit IPermitter.CapUpdated(IPermitter.CapType.TOKENS_PER_BIDDER, MAX_TOKENS_PER_BIDDER, newCap);

    vm.prank(owner);
    permitter.updateMaxTokensPerBidder(newCap);

    assertEq(permitter.maxTokensPerBidder(), newCap);
  }

  function test_RevertIf_UpdateMaxTokensPerBidderCalledByNonOwner() public {
    vm.expectRevert(IPermitter.Unauthorized.selector);
    vm.prank(bidder);
    permitter.updateMaxTokensPerBidder(2000 ether);
  }

  function test_UpdateTrustedSigner() public {
    address newSigner = makeAddr("newSigner");

    vm.expectEmit(true, true, false, false);
    emit IPermitter.SignerUpdated(trustedSigner, newSigner);

    vm.prank(owner);
    permitter.updateTrustedSigner(newSigner);

    assertEq(permitter.trustedSigner(), newSigner);
  }

  function test_RevertIf_UpdateTrustedSignerCalledByNonOwner() public {
    vm.expectRevert(IPermitter.Unauthorized.selector);
    vm.prank(bidder);
    permitter.updateTrustedSigner(makeAddr("newSigner"));
  }

  function test_RevertIf_UpdateTrustedSignerWithZeroAddress() public {
    vm.expectRevert(IPermitter.InvalidTrustedSigner.selector);
    vm.prank(owner);
    permitter.updateTrustedSigner(address(0));
  }

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

/// @notice Tests for signer rotation.
contract SignerRotation is PermitterTest {
  function test_OldSignerInvalidAfterRotation() public {
    uint256 expiry = block.timestamp + 1 hours;

    // Create a permit with the old signer
    bytes memory oldPermitData = _createPermitSignature(bidder, MAX_TOKENS_PER_BIDDER, expiry);

    // Rotate to new signer
    uint256 newSignerKey = 0x5678;
    address newSigner = vm.addr(newSignerKey);
    vm.prank(owner);
    permitter.updateTrustedSigner(newSigner);

    // Old permit should fail
    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.InvalidSignature.selector, newSigner, trustedSigner)
    );
    permitter.validateBid(bidder, 100 ether, 1 ether, oldPermitData);
  }

  function test_NewSignerWorksAfterRotation() public {
    uint256 newSignerKey = 0x5678;
    address newSigner = vm.addr(newSignerKey);

    // Rotate to new signer
    vm.prank(owner);
    permitter.updateTrustedSigner(newSigner);

    // Create a permit with the new signer
    uint256 expiry = block.timestamp + 1 hours;
    bytes memory newPermitData =
      _createPermitSignatureWithKey(bidder, MAX_TOKENS_PER_BIDDER, expiry, newSignerKey);

    // New permit should work
    bool result = permitter.validateBid(bidder, 100 ether, 1 ether, newPermitData);
    assertTrue(result);
  }
}

/// @notice Tests for view functions.
contract ViewFunctions is PermitterTest {
  function test_GetBidAmount() public {
    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permitData = _createPermitSignature(bidder, MAX_TOKENS_PER_BIDDER, expiry);

    assertEq(permitter.getBidAmount(bidder), 0);

    permitter.validateBid(bidder, 100 ether, 1 ether, permitData);
    assertEq(permitter.getBidAmount(bidder), 100 ether);

    permitter.validateBid(bidder, 50 ether, 0.5 ether, permitData);
    assertEq(permitter.getBidAmount(bidder), 150 ether);
  }

  function test_GetTotalEthRaised() public {
    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permitData1 = _createPermitSignature(bidder, MAX_TOKENS_PER_BIDDER, expiry);
    bytes memory permitData2 = _createPermitSignature(otherBidder, MAX_TOKENS_PER_BIDDER, expiry);

    assertEq(permitter.getTotalEthRaised(), 0);

    permitter.validateBid(bidder, 100 ether, 5 ether, permitData1);
    assertEq(permitter.getTotalEthRaised(), 5 ether);

    permitter.validateBid(otherBidder, 200 ether, 10 ether, permitData2);
    assertEq(permitter.getTotalEthRaised(), 15 ether);
  }

  function test_DomainSeparator() public view {
    bytes32 domainSeparator = permitter.domainSeparator();
    // Just verify it returns a non-zero value (actual value depends on contract address and chain)
    assertTrue(domainSeparator != bytes32(0));
  }
}
