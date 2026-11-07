// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {LayoverCredit} from "./LayoverCredit.sol";

/// @notice LAYC's only minter, behind an ERC1967 proxy that is LAYC's owner. Issuance pays for units of service the minion
/// bought as buyer of last resort, and nothing else:
/// - Epochs: anyone calls advance(), which advances LAYC's epoch; LAYC itself allows that once per 24 hours.
/// - Book: the minion signs Book(epoch, units) once per epoch, units >= 4; the floor is reward(epoch) / units, fixed for
///   the epoch.
/// - Units: the minion signs Unit(unitId, operator, epoch, workDigest) for a unit it bought and saw served; anyone submits
///   it during that epoch and the floor is minted to the operator. Each unitId is paid once. A unit a real buyer outbid the
///   minion for is paid by that buyer and the minion does not sign it.
/// - Caps: at most `units` units and reward(epoch) LAYC per epoch (LAYC enforces the reward too), and at most
///   reward(epoch) / 4 per operator per epoch. Budget not paid out in an epoch is never minted.
/// The controller can replace the minion key (effective MINION_DELAY after it is named, so a swap is public first), hand
/// the role on in two steps, upgrade this contract, and renounce upgrades, after which the code is permanent. It has no
/// call that mints or moves LAYC. Whoever holds the minion key can direct each epoch's reward, so the controller, as the
/// key's custodian, can too through setMinion. Until upgrades are renounced an upgrade can change the rule, but LAYC still
/// bounds any minter to one reward per 24 hours and the 21M cap.
contract LastResortBuyer is Initializable, UUPSUpgradeable {
    uint256 public constant MINION_DELAY = 1 days;
    uint256 public constant MAX_SHARE = 4;
    bytes32 public constant BOOK_TYPEHASH = keccak256("Book(uint256 epoch,uint256 units)");
    bytes32 public constant UNIT_TYPEHASH = keccak256("Unit(bytes32 unitId,address operator,uint256 epoch,bytes32 workDigest)");
    LayoverCredit public immutable token;

    address public controller;
    address public pendingController;
    address public minion;
    bool public upgradesRenounced;
    address public pendingMinion;
    uint256 public pendingMinionAt;
    mapping(uint256 => uint256) public units;
    mapping(uint256 => uint256) public paidUnits;
    mapping(uint256 => mapping(address => uint256)) public paidTo;
    mapping(bytes32 => bool) public paid;

    event ControllerTransferStarted(address indexed controller, address indexed pending);
    event ControllerTransferred(address indexed previous, address indexed controller);
    event MinionProposed(address indexed minion, uint256 at);
    event MinionSet(address indexed minion);
    event UpgradesRenounced();
    event Advanced(uint256 indexed epoch, uint256 reward);
    event BookCommitted(uint256 indexed epoch, uint256 units, uint256 floor);
    event UnitPaid(bytes32 indexed unitId, address indexed operator, uint256 indexed epoch, bytes32 workDigest, uint256 amount);

    constructor(LayoverCredit token_) {
        token = token_;
        _disableInitializers();
    }

    function initialize(address controller_, address minion_) external initializer {
        require(controller_ != address(0) && minion_ != address(0), "zero address");
        require(token.owner() == address(this) && token.totalSupply() == 0, "token");
        (controller, minion) = (controller_, minion_);
        emit ControllerTransferred(address(0), controller_);
        emit MinionSet(minion_);
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(abi.encode(keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("LastResortBuyer"), keccak256("1"), block.chainid, address(this)));
    }
    function floor(uint256 epoch) public view returns (uint256) {
        return units[epoch] == 0 ? 0 : token.reward(epoch) / units[epoch];
    }

    function advance() external {
        token.advanceEpoch();
        emit Advanced(token.epoch(), token.reward(token.epoch()));
    }

    function commitBook(uint256 epoch, uint256 units_, bytes calldata sig) external {
        require(epoch == token.epoch(), "not current epoch");
        require(units[epoch] == 0 && units_ >= MAX_SHARE && token.reward(epoch) / units_ > 0, "book");
        _signedByMinion(keccak256(abi.encode(BOOK_TYPEHASH, epoch, units_)), sig);
        units[epoch] = units_;
        emit BookCommitted(epoch, units_, floor(epoch));
    }

    function claim(bytes32 unitId, address operator, uint256 epoch, bytes32 workDigest, bytes calldata sig) external {
        require(epoch == token.epoch(), "not current epoch");
        require(units[epoch] > 0, "no book");
        require(!paid[unitId], "unit paid");
        _signedByMinion(keccak256(abi.encode(UNIT_TYPEHASH, unitId, operator, epoch, workDigest)), sig);
        uint256 amount = floor(epoch);
        require(++paidUnits[epoch] <= units[epoch], "book full");
        require((paidTo[epoch][operator] += amount) <= token.reward(epoch) / MAX_SHARE, "operator cap");
        paid[unitId] = true;
        token.mint(operator, amount);
        emit UnitPaid(unitId, operator, epoch, workDigest, amount);
    }

    function _signedByMinion(bytes32 structHash, bytes calldata sig) private view {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
        require(ECDSA.recover(digest, sig) == minion, "not minion");
    }

    modifier onlyController() { require(msg.sender == controller, "controller only"); _; }
    function setMinion(address minion_) external onlyController {
        require(minion_ != address(0), "zero address");
        (pendingMinion, pendingMinionAt) = (minion_, block.timestamp + MINION_DELAY);
        emit MinionProposed(minion_, pendingMinionAt);
    }
    function activateMinion() external {
        require(pendingMinion != address(0) && block.timestamp >= pendingMinionAt, "no minion due");
        (minion, pendingMinion) = (pendingMinion, address(0));
        emit MinionSet(minion);
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
    }
}
