// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {Permitter} from "src/Permitter.sol";
import {PermitterFactory} from "src/PermitterFactory.sol";
import {IPermitter} from "src/interfaces/IPermitter.sol";

/// @notice Fuzz tests for the Permitter system.
contract FuzzTest is Test {
  Permitter public permitter;
  PermitterFactory public factory;

  address public owner = makeAddr("owner");
  address public trustedSigner;
  uint256 public signerPrivateKey;
  address public authorizedCaller = makeAddr("authorizedCaller");

  uint256 public constant MAX_TOTAL_ETH = 100 ether;
  uint256 public constant MAX_TOKENS_PER_BIDDER = 1000 ether;
  uint256 public constant MIN_TOKENS_PER_BIDDER = 10 ether;

  bytes32 public constant PERMIT_TYPEHASH = keccak256("Permit(address bidder,uint256 expiry)");

  function setUp() public {
    signerPrivateKey = 0x1234;
    trustedSigner = vm.addr(signerPrivateKey);

    factory = new PermitterFactory();
    permitter = new Permitter(
      trustedSigner,
      MAX_TOTAL_ETH,
      MAX_TOKENS_PER_BIDDER,
      MIN_TOKENS_PER_BIDDER,
      owner,
      authorizedCaller
    );
  }

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

/// @notice Fuzz tests for signature verification.
contract SignatureVerificationFuzz is FuzzTest {
  /// @notice Fuzz test that random signatures are rejected.
  function testFuzz_RandomSignaturesAreRejected(
    address bidder,
    uint256 bidAmount,
    uint256 expiry,
    bytes memory randomSignature
  ) public {
    vm.assume(bidder != address(0));
    vm.assume(bidAmount >= MIN_TOKENS_PER_BIDDER && bidAmount <= MAX_TOKENS_PER_BIDDER);
    vm.assume(expiry > block.timestamp);

    // Create a permit struct without a valid signature
    IPermitter.Permit memory permit = IPermitter.Permit({bidder: bidder, expiry: expiry});

    bytes memory permitData = abi.encode(permit, randomSignature);

    // Should revert with either InvalidSignature or an ECDSA error
    vm.expectRevert();
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder, bidAmount, 1, permitData);
  }

  /// @notice Fuzz test that signatures from wrong signer are rejected.
  function testFuzz_WrongSignerRejected(address bidder, uint256 wrongSignerKey) public {
    vm.assume(bidder != address(0));
    // Ensure wrong signer key is valid (non-zero, less than secp256k1 order)
    vm.assume(wrongSignerKey > 0 && wrongSignerKey < type(uint256).max / 2);
    vm.assume(vm.addr(wrongSignerKey) != trustedSigner);

    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permitData = _createPermitSignatureWithKey(bidder, expiry, wrongSignerKey);

    address recoveredSigner = vm.addr(wrongSignerKey);

    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.InvalidSignature.selector, trustedSigner, recoveredSigner)
    );
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder, 100 ether, 1 ether, permitData);
  }

  /// @notice Fuzz test that valid signatures are accepted.
  function testFuzz_ValidSignaturesAccepted(
    address bidder,
    uint256 bidAmount,
    uint256 ethValue,
    uint256 expiryOffset
  ) public {
    vm.assume(bidder != address(0));
    bidAmount = bound(bidAmount, MIN_TOKENS_PER_BIDDER, MAX_TOKENS_PER_BIDDER);
    ethValue = bound(ethValue, 1, MAX_TOTAL_ETH);
    expiryOffset = bound(expiryOffset, 1, 365 days - 1);

    uint256 expiry = block.timestamp + expiryOffset;
    bytes memory permitData = _createPermitSignature(bidder, expiry);

    vm.prank(authorizedCaller);
    bool result = permitter.validateBid(bidder, bidAmount, ethValue, permitData);

    assertTrue(result);
    assertEq(permitter.getBidAmount(bidder), bidAmount);
    assertEq(permitter.getTotalEthRaised(), ethValue);
  }
}

/// @notice Fuzz tests for cap enforcement.
contract CapEnforcementFuzz is FuzzTest {
  /// @notice Fuzz test that cumulative bids never exceed maxTokensPerBidder.
  function testFuzz_CumulativeBidsNeverExceedMaxTokensPerBidder(uint256 numBids, uint256 seed)
    public
  {
    numBids = bound(numBids, 1, 10);

    address bidder = makeAddr("fuzzBidder");
    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permitData = _createPermitSignature(bidder, expiry);

    uint256 totalBid = 0;

    for (uint256 i = 0; i < numBids; i++) {
      // Generate deterministic random bid amounts from seed, at least MIN_TOKENS_PER_BIDDER
      uint256 bidAmount =
        bound(uint256(keccak256(abi.encode(seed, i))), MIN_TOKENS_PER_BIDDER, MAX_TOKENS_PER_BIDDER);

      if (totalBid + bidAmount <= MAX_TOKENS_PER_BIDDER) {
        // Bid should succeed
        vm.prank(authorizedCaller);
        permitter.validateBid(bidder, bidAmount, 0, permitData);
        totalBid += bidAmount;
        assertEq(permitter.getBidAmount(bidder), totalBid);
      } else {
        // Bid should fail
        vm.expectRevert(
          abi.encodeWithSelector(
            IPermitter.ExceedsPersonalCap.selector, bidAmount, MAX_TOKENS_PER_BIDDER, totalBid
          )
        );
        vm.prank(authorizedCaller);
        permitter.validateBid(bidder, bidAmount, 0, permitData);
      }
    }

    // Invariant: cumulative bids should never exceed maxTokensPerBidder
    assertLe(permitter.getBidAmount(bidder), MAX_TOKENS_PER_BIDDER);
  }

  /// @notice Fuzz test that total ETH raised never exceeds max.
  function testFuzz_TotalEthNeverExceedsMax(uint256 numBids, uint256 seed) public {
    numBids = bound(numBids, 1, 10);

    uint256 expiry = block.timestamp + 1 hours;
    uint256 totalEth = 0;

    for (uint256 i = 0; i < numBids; i++) {
      // forge-lint: disable-next-line(unsafe-typecast)
      address bidder = address(uint160(i + 1));
      // Generate deterministic random ETH values from seed
      uint256 ethValue = bound(uint256(keccak256(abi.encode(seed, i))), 1, MAX_TOTAL_ETH);

      bytes memory permitData = _createPermitSignature(bidder, expiry);

      if (totalEth + ethValue <= MAX_TOTAL_ETH) {
        // Should succeed
        vm.prank(authorizedCaller);
        permitter.validateBid(bidder, 100 ether, ethValue, permitData);
        totalEth += ethValue;
        assertEq(permitter.getTotalEthRaised(), totalEth);
      } else {
        // Should fail
        vm.expectRevert(
          abi.encodeWithSelector(
            IPermitter.ExceedsTotalCap.selector, ethValue, MAX_TOTAL_ETH, totalEth
          )
        );
        vm.prank(authorizedCaller);
        permitter.validateBid(bidder, 100 ether, ethValue, permitData);
      }
    }

    // Invariant: total ETH raised should never exceed max
    assertLe(permitter.getTotalEthRaised(), MAX_TOTAL_ETH);
  }
}

/// @notice Fuzz tests for expiry enforcement.
contract ExpiryEnforcementFuzz is FuzzTest {
  /// @notice Fuzz test that expired permits are always rejected.
  function testFuzz_ExpiredPermitsRejected(address bidder, uint256 timePastExpiry) public {
    vm.assume(bidder != address(0));
    vm.assume(timePastExpiry > 0 && timePastExpiry < 365 days);

    uint256 expiry = block.timestamp;
    bytes memory permitData = _createPermitSignature(bidder, expiry);

    // Warp past expiry
    vm.warp(expiry + timePastExpiry);

    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.SignatureExpired.selector, expiry, block.timestamp)
    );
    vm.prank(authorizedCaller);
    permitter.validateBid(bidder, 100 ether, 1 ether, permitData);
  }

  /// @notice Fuzz test that non-expired permits are accepted.
  function testFuzz_NonExpiredPermitsAccepted(address bidder, uint256 timeBeforeExpiry) public {
    vm.assume(bidder != address(0));
    vm.assume(timeBeforeExpiry > 0 && timeBeforeExpiry < 365 days);

    uint256 expiry = block.timestamp + timeBeforeExpiry;
    bytes memory permitData = _createPermitSignature(bidder, expiry);

    // Warp to just before expiry
    vm.warp(expiry - 1);

    vm.prank(authorizedCaller);
    bool result = permitter.validateBid(bidder, 100 ether, 1 ether, permitData);
    assertTrue(result);
  }
}

/// @notice Fuzz tests for owner functions.
contract OwnerFunctionsFuzz is FuzzTest {
  /// @notice Fuzz test that non-owners cannot schedule cap updates.
  function testFuzz_NonOwnerCannotScheduleMaxTotalEth(address caller, uint256 newCap) public {
    vm.assume(caller != owner);
    vm.assume(newCap > 0); // Must be > 0 for valid cap

    vm.expectRevert(IPermitter.Unauthorized.selector);
    vm.prank(caller);
    permitter.scheduleUpdateMaxTotalEth(newCap);
  }

  /// @notice Fuzz test that non-owners cannot schedule per-bidder cap updates.
  function testFuzz_NonOwnerCannotScheduleMaxTokensPerBidder(address caller, uint256 newCap) public {
    vm.assume(caller != owner);
    vm.assume(newCap > 0); // Must be > 0 for valid cap

    vm.expectRevert(IPermitter.Unauthorized.selector);
    vm.prank(caller);
    permitter.scheduleUpdateMaxTokensPerBidder(newCap);
  }

  /// @notice Fuzz test that non-owners cannot schedule signer updates.
  function testFuzz_NonOwnerCannotScheduleSigner(address caller, address newSigner) public {
    vm.assume(caller != owner);
    vm.assume(newSigner != address(0)); // Must be non-zero for valid signer

    vm.expectRevert(IPermitter.Unauthorized.selector);
    vm.prank(caller);
    permitter.scheduleUpdateTrustedSigner(newSigner);
  }

  /// @notice Fuzz test that non-owners cannot pause.
  function testFuzz_NonOwnerCannotPause(address caller) public {
    vm.assume(caller != owner);

    vm.expectRevert(IPermitter.Unauthorized.selector);
    vm.prank(caller);
    permitter.pause();
  }

  /// @notice Fuzz test that owner can schedule and execute cap updates (after timelock).
  function testFuzz_OwnerCanUpdateCapsWithTimelock(uint256 newTotalEth, uint256 newPerBidder)
    public
  {
    // Bound to valid non-zero values
    newTotalEth = bound(newTotalEth, 1, type(uint256).max);
    newPerBidder = bound(newPerBidder, 1, type(uint256).max);

    vm.startPrank(owner);

    // Schedule updates
    permitter.scheduleUpdateMaxTotalEth(newTotalEth);
    permitter.scheduleUpdateMaxTokensPerBidder(newPerBidder);

    // Advance past timelock
    vm.warp(block.timestamp + 1 hours + 1);

    // Execute updates
    permitter.executeUpdateMaxTotalEth();
    assertEq(permitter.maxTotalEth(), newTotalEth);

    permitter.executeUpdateMaxTokensPerBidder();
    assertEq(permitter.maxTokensPerBidder(), newPerBidder);

    vm.stopPrank();
  }
}

/// @notice Fuzz tests for factory.
contract FactoryFuzz is FuzzTest {
  /// @notice Fuzz test that CREATE2 addresses are deterministic.
  function testFuzz_Create2AddressesAreDeterministic(
    address deployer,
    address fuzzedTrustedSigner,
    uint256 maxTotalEth,
    uint256 maxTokensPerBidder,
    uint256 minTokensPerBidder,
    address fuzzedOwner,
    address fuzzedAuthorizedCaller,
    bytes32 salt
  ) public {
    vm.assume(deployer != address(0));
    vm.assume(fuzzedTrustedSigner != address(0));
    vm.assume(fuzzedOwner != address(0));
    // Bound to valid non-zero caps
    maxTotalEth = bound(maxTotalEth, 1, type(uint256).max);
    maxTokensPerBidder = bound(maxTokensPerBidder, 1, type(uint256).max);
    minTokensPerBidder = bound(minTokensPerBidder, 0, maxTokensPerBidder);

    vm.startPrank(deployer);

    address predicted = factory.predictPermitterAddress(
      fuzzedTrustedSigner,
      maxTotalEth,
      maxTokensPerBidder,
      minTokensPerBidder,
      fuzzedOwner,
      fuzzedAuthorizedCaller,
      salt
    );

    address actual = factory.createPermitter(
      fuzzedTrustedSigner,
      maxTotalEth,
      maxTokensPerBidder,
      minTokensPerBidder,
      fuzzedOwner,
      fuzzedAuthorizedCaller,
      salt
    );

    vm.stopPrank();

    assertEq(predicted, actual);
  }

  /// @notice Fuzz test that different salts produce different addresses.
  function testFuzz_DifferentSaltsDifferentAddresses(bytes32 salt1, bytes32 salt2) public {
    vm.assume(salt1 != salt2);

    address deployer = makeAddr("fuzzDeployer");

    vm.startPrank(deployer);

    address addr1 = factory.predictPermitterAddress(
      trustedSigner,
      MAX_TOTAL_ETH,
      MAX_TOKENS_PER_BIDDER,
      MIN_TOKENS_PER_BIDDER,
      owner,
      authorizedCaller,
      salt1
    );

    address addr2 = factory.predictPermitterAddress(
      trustedSigner,
      MAX_TOTAL_ETH,
      MAX_TOKENS_PER_BIDDER,
      MIN_TOKENS_PER_BIDDER,
      owner,
      authorizedCaller,
      salt2
    );

    vm.stopPrank();

    assertTrue(addr1 != addr2);
  }

  /// @notice Fuzz test that different deployers with same salt produce different addresses.
  function testFuzz_DifferentDeployersDifferentAddresses(
    address deployer1,
    address deployer2,
    bytes32 salt
  ) public {
    vm.assume(deployer1 != deployer2);
    vm.assume(deployer1 != address(0));
    vm.assume(deployer2 != address(0));

    vm.prank(deployer1);
    address addr1 = factory.predictPermitterAddress(
      trustedSigner,
      MAX_TOTAL_ETH,
      MAX_TOKENS_PER_BIDDER,
      MIN_TOKENS_PER_BIDDER,
      owner,
      authorizedCaller,
      salt
    );

    vm.prank(deployer2);
    address addr2 = factory.predictPermitterAddress(
      trustedSigner,
      MAX_TOTAL_ETH,
      MAX_TOKENS_PER_BIDDER,
      MIN_TOKENS_PER_BIDDER,
      owner,
      authorizedCaller,
      salt
    );

    assertTrue(addr1 != addr2);
  }
}
