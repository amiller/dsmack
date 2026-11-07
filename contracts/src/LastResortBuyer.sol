// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {LayoverCredit} from "./LayoverCredit.sol";
import {DstackKmsChain} from "./DstackKmsChain.sol";

/// @notice LAYC's only minter, behind an ERC1967 proxy that is LAYC's owner. Issuance pays for units of service bought by
/// an attested minion as buyer of last resort, and nothing else:
/// - Minions: a minion is any CVM of an approved dstack app. It registers the key GetKey derives for PURPOSE with the key's
///   signature chain: the app key signs the derived key, and the KMS root (kmsRoot, fixed at deploy) signs the app key for
///   the app id. The KMS releases an app's key only to a compose hash the app's on-chain DstackApp contract allows, so the
///   minion's code is governed there. Every registered key of an approved app may sign, so minions are interchangeable.
///   Removing an app stops its minions at once; revokeMinion stops one key at once, for good.
/// - Epochs: anyone calls advance(), which advances LAYC's epoch; LAYC itself allows that once per 24 hours.
/// - Book: a minion signs Book(epoch, units) once per epoch, units >= 4, within BOOK_WINDOW of the epoch's start; the floor
///   is min(reward(epoch) / units, MAX_FLOOR), fixed for the epoch.
/// - Units: a minion signs Unit(unitId, operator, epoch, workDigest) for a unit it bought and saw served; anyone submits it
///   during that epoch and the floor is minted to the operator. Each unitId is paid once.
/// - Caps: at most `units` units per epoch, each at most MAX_FLOOR, never more than reward(epoch) (LAYC enforces the reward
///   too), and at most reward(epoch) / 4 per operator per epoch. Budget not paid out in an epoch is never minted.
/// At deploy no app is approved and no minion is registered, so nothing mints until the first minion registers.
/// The controller approves and removes apps, revokes minion keys, hands the role on in two steps, upgrades this contract
/// and can renounce upgrades. It has no call that mints or moves LAYC; by approving an app it decides which code may sign.
contract LastResortBuyer is Initializable, UUPSUpgradeable {
    uint256 public constant MAX_SHARE = 4;
    /// A unit pays at most 1 LAYC, whatever the book's size, so issuance tracks units served rather than the reward.
    uint256 public constant MAX_FLOOR = 1e6;
    /// The book for an epoch must be committed within BOOK_WINDOW of the epoch's start (LAYC's epochStart).
    uint256 public constant BOOK_WINDOW = 2 hours;
    bytes32 public constant BOOK_TYPEHASH = keccak256("Book(uint256 epoch,uint256 units)");
    bytes32 public constant UNIT_TYPEHASH = keccak256("Unit(bytes32 unitId,address operator,uint256 epoch,bytes32 workDigest)");
    /// The GetKey purpose a minion's signing key is derived for.
    string public constant PURPOSE = "layover-minion";
    LayoverCredit public immutable token;
    /// The dstack KMS root signer (on Base mainnet, Phala's Base KMS 0x2f83…Ba9C: 0x52d3CF51c8A37A2CCfC79bBb98c7810d7Dd4CE51).
    address public immutable kmsRoot;

    address public controller;
    address public pendingController;
    bool public upgradesRenounced;
    mapping(address => bool) public approvedApps;
    mapping(address => address) public minionApp;
    mapping(address => bool) public revokedMinion;
    mapping(uint256 => uint256) public units;
    mapping(uint256 => uint256) public paidUnits;
    mapping(uint256 => mapping(address => uint256)) public paidTo;
    mapping(bytes32 => bool) public paid;
    mapping(address => uint64) public appGeneration;
    mapping(address => uint64) public minionGeneration;

    event ControllerTransferStarted(address indexed controller, address indexed pending);
    event ControllerTransferred(address indexed previous, address indexed controller);
    event AppApproved(address indexed app, bool approved);
    event MinionRegistered(address indexed key, address indexed app);
    event MinionRevoked(address indexed key);
    event UpgradesRenounced();
    event Advanced(uint256 indexed epoch, uint256 reward);
    event BookCommitted(uint256 indexed epoch, uint256 units, uint256 floor, address minion);
    event UnitPaid(bytes32 indexed unitId, address indexed operator, uint256 indexed epoch, bytes32 workDigest, uint256 amount, address minion);

    constructor(LayoverCredit token_, address kmsRoot_) {
        require(kmsRoot_ != address(0), "kms root");
        (token, kmsRoot) = (token_, kmsRoot_);
        _disableInitializers();
    }

    function initialize(address controller_) external initializer {
        require(controller_ != address(0), "zero address");
        require(token.owner() == address(this) && token.totalSupply() == 0, "token");
        controller = controller_;
        emit ControllerTransferred(address(0), controller_);
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(abi.encode(keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("LastResortBuyer"), keccak256("1"), block.chainid, address(this)));
    }
    function floor(uint256 epoch) public view returns (uint256) {
        if (units[epoch] == 0) return 0;
        uint256 f = token.reward(epoch) / units[epoch];
        return f < MAX_FLOOR ? f : MAX_FLOOR;
    }
    /// @notice Anyone may submit a minion's GetKey(PURPOSE) result: its compressed pubkey, the app's compressed pubkey and
    /// the two signatures of signature_chain. Returns the registered key.
    function registerMinion(address app, bytes calldata derivedPubkey, bytes calldata appPubkey, bytes calldata appSignature,
        bytes calldata kmsSignature) external returns (address key) {
        require(approvedApps[app], "app not approved");
        key = DstackKmsChain.derivedSigner(kmsRoot, app, PURPOSE, derivedPubkey, appPubkey, appSignature, kmsSignature);
        require(!revokedMinion[key] && (minionApp[key] == address(0) || minionGeneration[key] != appGeneration[minionApp[key]]), "minion key");
        minionApp[key] = app;
        minionGeneration[key] = appGeneration[app];
        emit MinionRegistered(key, app);
    }

    function advance() external {
        token.advanceEpoch();
        emit Advanced(token.epoch(), token.reward(token.epoch()));
    }

    function commitBook(uint256 epoch, uint256 units_, bytes calldata sig) external {
        require(epoch == token.epoch(), "not current epoch");
        require(block.timestamp <= token.epochStart() + BOOK_WINDOW, "book window");
        require(units[epoch] == 0 && units_ >= MAX_SHARE && token.reward(epoch) / units_ > 0, "book");
        address m = _minion(keccak256(abi.encode(BOOK_TYPEHASH, epoch, units_)), sig);
        units[epoch] = units_;
        emit BookCommitted(epoch, units_, floor(epoch), m);
    }

    function claim(bytes32 unitId, address operator, uint256 epoch, bytes32 workDigest, bytes calldata sig) external {
        require(epoch == token.epoch(), "not current epoch");
        require(units[epoch] > 0, "no book");
        require(!paid[unitId], "unit paid");
        address m = _minion(keccak256(abi.encode(UNIT_TYPEHASH, unitId, operator, epoch, workDigest)), sig);
        uint256 amount = floor(epoch);
        require(++paidUnits[epoch] <= units[epoch], "book full");
        require((paidTo[epoch][operator] += amount) <= token.reward(epoch) / MAX_SHARE, "operator cap");
        paid[unitId] = true;
        token.mint(operator, amount);
        emit UnitPaid(unitId, operator, epoch, workDigest, amount, m);
    }

    /// A key that registered under an app still approved, and was not revoked.
    function isMinion(address key) public view returns (bool) {
        return minionApp[key] != address(0) && approvedApps[minionApp[key]] && !revokedMinion[key]
            && minionGeneration[key] == appGeneration[minionApp[key]];
    }
    function _minion(bytes32 structHash, bytes calldata sig) private view returns (address m) {
        m = ECDSA.recover(keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash)), sig);
        require(isMinion(m), "not minion");
    }

    modifier onlyController() { require(msg.sender == controller, "controller only"); _; }
    function approveApp(address app) external onlyController {
        appGeneration[app]++;
        approvedApps[app] = true;
        emit AppApproved(app, true);
    }
    /// @notice Every minion registered under the app stops signing at once.
    function removeApp(address app) external onlyController {
        approvedApps[app] = false;
        emit AppApproved(app, false);
    }
    /// @notice At once and for good: the key can neither sign nor register again.
    function revokeMinion(address key) external onlyController {
        revokedMinion[key] = true;
        emit MinionRevoked(key);
    }
    function transferController(address next) external onlyController {
        pendingController = next;
        emit ControllerTransferStarted(controller, next);
    }
    function acceptController() external {
        require(msg.sender == pendingController, "pending controller only");
        emit ControllerTransferred(controller, msg.sender);
        (controller, pendingController) = (msg.sender, address(0));
    }
    function renounceUpgrades() external onlyController {
        upgradesRenounced = true;
        emit UpgradesRenounced();
    }
    function _authorizeUpgrade(address next) internal view override onlyController {
        require(!upgradesRenounced, "upgrades renounced");
        require(LastResortBuyer(next).token() == token, "token");
        require(LastResortBuyer(next).kmsRoot() == kmsRoot, "kms root");
    }
}
