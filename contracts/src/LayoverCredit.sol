// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @notice Layover Credit (LAYC): 6-decimal ERC-20 with EIP-3009 (transferWithAuthorization, receiveWithAuthorization,
/// cancelAuthorization) so x402-style deposits land through an escrow's depositWithAuthorization.
/// Supply is capped at 21,000,000. The constructor mints the genesis pot to the owner; after that the owner mints at most
/// reward(epoch) per epoch, and the reward halves every HALVING_EPOCHS epochs (7,187 per epoch at first: daily epochs over
/// four-year halvings give ~21M). The owner advances the epoch. What triggers an advance (time, revenue, or verified paid
/// volume) is nikete's decision and is not enforced here; an epoch's unminted reward does not roll forward.
contract LayoverCredit {
    string public constant name = "Layover Credit";
    string public constant symbol = "LAYC";
    string public constant version = "1";
    uint8 public constant decimals = 6;
    uint256 public constant CAP = 21_000_000e6;
    uint256 public constant INITIAL_REWARD = 7_187e6;
    uint256 public constant HALVING_EPOCHS = 1461;
    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");
    bytes32 public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH = keccak256("ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");
    bytes32 public constant CANCEL_AUTHORIZATION_TYPEHASH = keccak256("CancelAuthorization(address authorizer,bytes32 nonce)");
    uint256 private constant HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    address public immutable owner;
    uint256 public totalSupply;
    uint256 public epoch;
    uint256 public mintedInEpoch;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => mapping(bytes32 => bool)) public authorizationState;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);
    event AuthorizationCanceled(address indexed authorizer, bytes32 indexed nonce);
    event EpochAdvanced(uint256 epoch, uint256 reward);

    constructor(address owner_, uint256 genesis) {
        require(owner_ != address(0) && genesis <= CAP, "owner/genesis");
        owner = owner_;
        _mint(owner_, genesis);
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(abi.encode(keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes(name)), keccak256(bytes(version)), block.chainid, address(this)));
    }
    function reward(uint256 e) public pure returns (uint256) { return INITIAL_REWARD >> (e / HALVING_EPOCHS); }

    function advanceEpoch() external {
        require(msg.sender == owner, "owner only");
        epoch += 1; mintedInEpoch = 0;
        emit EpochAdvanced(epoch, reward(epoch));
    }
    function mint(address to, uint256 amount) external {
        require(msg.sender == owner, "owner only");
        require(mintedInEpoch + amount <= reward(epoch), "epoch reward");
        mintedInEpoch += amount;
        _mint(to, amount);
    }
    function _mint(address to, uint256 amount) private {
        require(to != address(0) && totalSupply + amount <= CAP, "cap");
        totalSupply += amount; balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }
    function transfer(address to, uint256 amount) external returns (bool) { _transfer(msg.sender, to, amount); return true; }
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        if (a != type(uint256).max) allowance[from][msg.sender] = a - amount;
        _transfer(from, to, amount);
        return true;
    }
    function _transfer(address from, address to, uint256 amount) private {
        require(to != address(0), "zero address");
        balanceOf[from] -= amount; balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }

    function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore,
        bytes32 nonce, uint8 v, bytes32 r, bytes32 s) external {
        _authorize(from, nonce, validAfter, validBefore, keccak256(abi.encode(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce)), v, r, s);
        _transfer(from, to, value);
    }
    /// @notice As transferWithAuthorization, but only the payee may submit it, so a front-runner cannot execute it first.
    function receiveWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore,
        bytes32 nonce, uint8 v, bytes32 r, bytes32 s) external {
        require(to == msg.sender, "caller must be the payee");
        _authorize(from, nonce, validAfter, validBefore, keccak256(abi.encode(RECEIVE_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce)), v, r, s);
        _transfer(from, to, value);
    }
    function cancelAuthorization(address authorizer, bytes32 nonce, uint8 v, bytes32 r, bytes32 s) external {
        _use(authorizer, nonce, keccak256(abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, authorizer, nonce)), v, r, s);
        emit AuthorizationCanceled(authorizer, nonce);
    }
    function _authorize(address from, bytes32 nonce, uint256 validAfter, uint256 validBefore, bytes32 structHash, uint8 v, bytes32 r, bytes32 s) private {
        require(block.timestamp > validAfter && block.timestamp < validBefore, "authorization time");
        _use(from, nonce, structHash, v, r, s);
        emit AuthorizationUsed(from, nonce);
    }
    function _use(address who, bytes32 nonce, bytes32 structHash, uint8 v, bytes32 r, bytes32 s) private {
        require(!authorizationState[who][nonce], "authorization used");
        require(uint256(s) <= HALF_ORDER && (v == 27 || v == 28), "signature canonical");
        address signer = ecrecover(keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash)), v, r, s);
        require(signer != address(0) && signer == who, "invalid signature");
        authorizationState[who][nonce] = true;
    }
}
