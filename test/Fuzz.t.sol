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

  uint256 public constant MAX_TOTAL_ETH = 100 ether;
  uint256 public constant MAX_TOKENS_PER_BIDDER = 1000 ether;

  bytes32 public constant PERMIT_TYPEHASH =
    keccak256("Permit(address bidder,uint256 maxBidAmount,uint256 expiry)");

  function setUp() public {
    signerPrivateKey = 0x1234;
    trustedSigner = vm.addr(signerPrivateKey);

    factory = new PermitterFactory();
    permitter = new Permitter(trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner);
  }

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
    vm.assume(bidAmount > 0 && bidAmount <= MAX_TOKENS_PER_BIDDER);
    vm.assume(expiry > block.timestamp);

    // Create a permit struct without a valid signature
    IPermitter.Permit memory permit =
      IPermitter.Permit({bidder: bidder, maxBidAmount: MAX_TOKENS_PER_BIDDER, expiry: expiry});

    bytes memory permitData = abi.encode(permit, randomSignature);

    // Should revert with either InvalidSignature or an ECDSA error
    vm.expectRevert();
    permitter.validateBid(bidder, bidAmount, 1, permitData);
  }

  /// @notice Fuzz test that signatures from wrong signer are rejected.
  function testFuzz_WrongSignerRejected(address bidder, uint256 wrongSignerKey) public {
    vm.assume(bidder != address(0));
    // Ensure wrong signer key is valid (non-zero, less than secp256k1 order)
    vm.assume(wrongSignerKey > 0 && wrongSignerKey < type(uint256).max / 2);
    vm.assume(vm.addr(wrongSignerKey) != trustedSigner);

    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permitData =
      _createPermitSignatureWithKey(bidder, MAX_TOKENS_PER_BIDDER, expiry, wrongSignerKey);

    address recoveredSigner = vm.addr(wrongSignerKey);

    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.InvalidSignature.selector, trustedSigner, recoveredSigner)
    );
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
    vm.assume(bidAmount > 0 && bidAmount <= MAX_TOKENS_PER_BIDDER);
    vm.assume(ethValue > 0 && ethValue <= MAX_TOTAL_ETH);
    vm.assume(expiryOffset > 0 && expiryOffset < 365 days);

    uint256 expiry = block.timestamp + expiryOffset;
    bytes memory permitData = _createPermitSignature(bidder, MAX_TOKENS_PER_BIDDER, expiry);

    bool result = permitter.validateBid(bidder, bidAmount, ethValue, permitData);

    assertTrue(result);
    assertEq(permitter.getBidAmount(bidder), bidAmount);
    assertEq(permitter.getTotalEthRaised(), ethValue);
  }
}

/// @notice Fuzz tests for cap enforcement.
contract CapEnforcementFuzz is FuzzTest {
  /// @notice Fuzz test that cumulative bids never exceed permit max.
  function testFuzz_CumulativeBidsNeverExceedPermitMax(
    uint256 permitMax,
    uint256 numBids,
    uint256 seed
  ) public {
    permitMax = bound(permitMax, 1, MAX_TOKENS_PER_BIDDER);
    numBids = bound(numBids, 1, 10);

    address bidder = makeAddr("fuzzBidder");
    uint256 expiry = block.timestamp + 1 hours;
    bytes memory permitData = _createPermitSignature(bidder, permitMax, expiry);

    uint256 totalBid = 0;

    for (uint256 i = 0; i < numBids; i++) {
      // Generate deterministic random bid amounts from seed
      uint256 bidAmount = bound(uint256(keccak256(abi.encode(seed, i))), 1, permitMax);

      if (totalBid + bidAmount <= permitMax) {
        // Bid should succeed
        permitter.validateBid(bidder, bidAmount, 0, permitData);
        totalBid += bidAmount;
        assertEq(permitter.getBidAmount(bidder), totalBid);
      } else {
        // Bid should fail
        vm.expectRevert(
          abi.encodeWithSelector(
            IPermitter.ExceedsPersonalCap.selector, bidAmount, permitMax, totalBid
          )
        );
        permitter.validateBid(bidder, bidAmount, 0, permitData);
      }
    }

    // Invariant: cumulative bids should never exceed permit max
    assertLe(permitter.getBidAmount(bidder), permitMax);
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

      bytes memory permitData = _createPermitSignature(bidder, MAX_TOKENS_PER_BIDDER, expiry);

      if (totalEth + ethValue <= MAX_TOTAL_ETH) {
        // Should succeed
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
    bytes memory permitData = _createPermitSignature(bidder, MAX_TOKENS_PER_BIDDER, expiry);

    // Warp past expiry
    vm.warp(expiry + timePastExpiry);

    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.SignatureExpired.selector, expiry, block.timestamp)
    );
    permitter.validateBid(bidder, 100 ether, 1 ether, permitData);
  }

  /// @notice Fuzz test that non-expired permits are accepted.
  function testFuzz_NonExpiredPermitsAccepted(address bidder, uint256 timeBeforeExpiry) public {
    vm.assume(bidder != address(0));
    vm.assume(timeBeforeExpiry > 0 && timeBeforeExpiry < 365 days);

    uint256 expiry = block.timestamp + timeBeforeExpiry;
    bytes memory permitData = _createPermitSignature(bidder, MAX_TOKENS_PER_BIDDER, expiry);

    // Warp to just before expiry
    vm.warp(expiry - 1);

    bool result = permitter.validateBid(bidder, 100 ether, 1 ether, permitData);
    assertTrue(result);
  }
}

/// @notice Fuzz tests for owner functions.
contract OwnerFunctionsFuzz is FuzzTest {
  /// @notice Fuzz test that non-owners cannot update caps.
  function testFuzz_NonOwnerCannotUpdateMaxTotalEth(address caller, uint256 newCap) public {
    vm.assume(caller != owner);

    vm.expectRevert(IPermitter.Unauthorized.selector);
    vm.prank(caller);
    permitter.updateMaxTotalEth(newCap);
  }

  /// @notice Fuzz test that non-owners cannot update per-bidder cap.
  function testFuzz_NonOwnerCannotUpdateMaxTokensPerBidder(address caller, uint256 newCap) public {
    vm.assume(caller != owner);

    vm.expectRevert(IPermitter.Unauthorized.selector);
    vm.prank(caller);
    permitter.updateMaxTokensPerBidder(newCap);
  }

  /// @notice Fuzz test that non-owners cannot update signer.
  function testFuzz_NonOwnerCannotUpdateSigner(address caller, address newSigner) public {
    vm.assume(caller != owner);

    vm.expectRevert(IPermitter.Unauthorized.selector);
    vm.prank(caller);
    permitter.updateTrustedSigner(newSigner);
  }

  /// @notice Fuzz test that non-owners cannot pause.
  function testFuzz_NonOwnerCannotPause(address caller) public {
    vm.assume(caller != owner);

    vm.expectRevert(IPermitter.Unauthorized.selector);
    vm.prank(caller);
    permitter.pause();
  }

  /// @notice Fuzz test that owner can update caps to any value.
  function testFuzz_OwnerCanUpdateCaps(uint256 newTotalEth, uint256 newPerBidder) public {
    vm.startPrank(owner);

    permitter.updateMaxTotalEth(newTotalEth);
    assertEq(permitter.maxTotalEth(), newTotalEth);

    permitter.updateMaxTokensPerBidder(newPerBidder);
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
    address fuzzedOwner,
    bytes32 salt
  ) public {
    vm.assume(deployer != address(0));
    vm.assume(fuzzedTrustedSigner != address(0));
    vm.assume(fuzzedOwner != address(0));

    vm.startPrank(deployer);

    address predicted = factory.predictPermitterAddress(
      fuzzedTrustedSigner, maxTotalEth, maxTokensPerBidder, fuzzedOwner, salt
    );

    address actual = factory.createPermitter(
      fuzzedTrustedSigner, maxTotalEth, maxTokensPerBidder, fuzzedOwner, salt
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
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, salt1
    );

    address addr2 = factory.predictPermitterAddress(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, salt2
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
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, salt
    );

    vm.prank(deployer2);
    address addr2 = factory.predictPermitterAddress(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, salt
    );

    assertTrue(addr1 != addr2);
  }
}
