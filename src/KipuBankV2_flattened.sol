
// File: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.2/contracts/access/IAccessControl.sol


// OpenZeppelin Contracts (last updated v5.0.0) (access/IAccessControl.sol)

pragma solidity ^0.8.20;

/**
 * @dev External interface of AccessControl declared to support ERC165 detection.
 */
interface IAccessControl {
    /**
     * @dev The `account` is missing a role.
     */
    error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);

    /**
     * @dev The caller of a function is not the expected one.
     *
     * NOTE: Don't confuse with {AccessControlUnauthorizedAccount}.
     */
    error AccessControlBadConfirmation();

    /**
     * @dev Emitted when `newAdminRole` is set as ``role``'s admin role, replacing `previousAdminRole`
     *
     * `DEFAULT_ADMIN_ROLE` is the starting admin for all roles, despite
     * {RoleAdminChanged} not being emitted signaling this.
     */
    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);

    /**
     * @dev Emitted when `account` is granted `role`.
     *
     * `sender` is the account that originated the contract call, an admin role
     * bearer except when using {AccessControl-_setupRole}.
     */
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);

    /**
     * @dev Emitted when `account` is revoked `role`.
     *
     * `sender` is the account that originated the contract call:
     *   - if using `revokeRole`, it is the admin role bearer
     *   - if using `renounceRole`, it is the role bearer (i.e. `account`)
     */
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole(bytes32 role, address account) external view returns (bool);

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {AccessControl-_setRoleAdmin}.
     */
    function getRoleAdmin(bytes32 role) external view returns (bytes32);

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function grantRole(bytes32 role, address account) external;

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function revokeRole(bytes32 role, address account) external;

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {grantRole} and {revokeRole}: this function's
     * purpose is to provide a mechanism for accounts to lose their privileges
     * if they are compromised (such as when a trusted device is misplaced).
     *
     * If the calling account had been granted `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `callerConfirmation`.
     */
    function renounceRole(bytes32 role, address callerConfirmation) external;
}

// File: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.2/contracts/utils/Context.sol


// OpenZeppelin Contracts (last updated v5.0.1) (utils/Context.sol)

pragma solidity ^0.8.20;

/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }

    function _contextSuffixLength() internal view virtual returns (uint256) {
        return 0;
    }
}

// File: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.2/contracts/utils/introspection/IERC165.sol


// OpenZeppelin Contracts (last updated v5.0.0) (utils/introspection/IERC165.sol)

pragma solidity ^0.8.20;

/**
 * @dev Interface of the ERC165 standard, as defined in the
 * https://eips.ethereum.org/EIPS/eip-165[EIP].
 *
 * Implementers can declare support of contract interfaces, which can then be
 * queried by others ({ERC165Checker}).
 *
 * For an implementation, see {ERC165}.
 */
interface IERC165 {
    /**
     * @dev Returns true if this contract implements the interface defined by
     * `interfaceId`. See the corresponding
     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]
     * to learn more about how these ids are created.
     *
     * This function call must use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

// File: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.2/contracts/utils/introspection/ERC165.sol


// OpenZeppelin Contracts (last updated v5.0.0) (utils/introspection/ERC165.sol)

pragma solidity ^0.8.20;


/**
 * @dev Implementation of the {IERC165} interface.
 *
 * Contracts that want to implement ERC165 should inherit from this contract and override {supportsInterface} to check
 * for the additional interface id that will be supported. For example:
 *
 * ```solidity
 * function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
 *     return interfaceId == type(MyInterface).interfaceId || super.supportsInterface(interfaceId);
 * }
 * ```
 */
abstract contract ERC165 is IERC165 {
    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual returns (bool) {
        return interfaceId == type(IERC165).interfaceId;
    }
}

// File: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.2/contracts/access/AccessControl.sol


// OpenZeppelin Contracts (last updated v5.0.0) (access/AccessControl.sol)

pragma solidity ^0.8.20;




/**
 * @dev Contract module that allows children to implement role-based access
 * control mechanisms. This is a lightweight version that doesn't allow enumerating role
 * members except through off-chain means by accessing the contract event logs. Some
 * applications may benefit from on-chain enumerability, for those cases see
 * {AccessControlEnumerable}.
 *
 * Roles are referred to by their `bytes32` identifier. These should be exposed
 * in the external API and be unique. The best way to achieve this is by
 * using `public constant` hash digests:
 *
 * ```solidity
 * bytes32 public constant MY_ROLE = keccak256("MY_ROLE");
 * ```
 *
 * Roles can be used to represent a set of permissions. To restrict access to a
 * function call, use {hasRole}:
 *
 * ```solidity
 * function foo() public {
 *     require(hasRole(MY_ROLE, msg.sender));
 *     ...
 * }
 * ```
 *
 * Roles can be granted and revoked dynamically via the {grantRole} and
 * {revokeRole} functions. Each role has an associated admin role, and only
 * accounts that have a role's admin role can call {grantRole} and {revokeRole}.
 *
 * By default, the admin role for all roles is `DEFAULT_ADMIN_ROLE`, which means
 * that only accounts with this role will be able to grant or revoke other
 * roles. More complex role relationships can be created by using
 * {_setRoleAdmin}.
 *
 * WARNING: The `DEFAULT_ADMIN_ROLE` is also its own admin: it has permission to
 * grant and revoke this role. Extra precautions should be taken to secure
 * accounts that have been granted it. We recommend using {AccessControlDefaultAdminRules}
 * to enforce additional security measures for this role.
 */
abstract contract AccessControl is Context, IAccessControl, ERC165 {
    struct RoleData {
        mapping(address account => bool) hasRole;
        bytes32 adminRole;
    }

    mapping(bytes32 role => RoleData) private _roles;

    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    /**
     * @dev Modifier that checks that an account has a specific role. Reverts
     * with an {AccessControlUnauthorizedAccount} error including the required role.
     */
    modifier onlyRole(bytes32 role) {
        _checkRole(role);
        _;
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IAccessControl).interfaceId || super.supportsInterface(interfaceId);
    }

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole(bytes32 role, address account) public view virtual returns (bool) {
        return _roles[role].hasRole[account];
    }

    /**
     * @dev Reverts with an {AccessControlUnauthorizedAccount} error if `_msgSender()`
     * is missing `role`. Overriding this function changes the behavior of the {onlyRole} modifier.
     */
    function _checkRole(bytes32 role) internal view virtual {
        _checkRole(role, _msgSender());
    }

    /**
     * @dev Reverts with an {AccessControlUnauthorizedAccount} error if `account`
     * is missing `role`.
     */
    function _checkRole(bytes32 role, address account) internal view virtual {
        if (!hasRole(role, account)) {
            revert AccessControlUnauthorizedAccount(account, role);
        }
    }

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {_setRoleAdmin}.
     */
    function getRoleAdmin(bytes32 role) public view virtual returns (bytes32) {
        return _roles[role].adminRole;
    }

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     *
     * May emit a {RoleGranted} event.
     */
    function grantRole(bytes32 role, address account) public virtual onlyRole(getRoleAdmin(role)) {
        _grantRole(role, account);
    }

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     *
     * May emit a {RoleRevoked} event.
     */
    function revokeRole(bytes32 role, address account) public virtual onlyRole(getRoleAdmin(role)) {
        _revokeRole(role, account);
    }

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {grantRole} and {revokeRole}: this function's
     * purpose is to provide a mechanism for accounts to lose their privileges
     * if they are compromised (such as when a trusted device is misplaced).
     *
     * If the calling account had been revoked `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `callerConfirmation`.
     *
     * May emit a {RoleRevoked} event.
     */
    function renounceRole(bytes32 role, address callerConfirmation) public virtual {
        if (callerConfirmation != _msgSender()) {
            revert AccessControlBadConfirmation();
        }

        _revokeRole(role, callerConfirmation);
    }

    /**
     * @dev Sets `adminRole` as ``role``'s admin role.
     *
     * Emits a {RoleAdminChanged} event.
     */
    function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal virtual {
        bytes32 previousAdminRole = getRoleAdmin(role);
        _roles[role].adminRole = adminRole;
        emit RoleAdminChanged(role, previousAdminRole, adminRole);
    }

    /**
     * @dev Attempts to grant `role` to `account` and returns a boolean indicating if `role` was granted.
     *
     * Internal function without access restriction.
     *
     * May emit a {RoleGranted} event.
     */
    function _grantRole(bytes32 role, address account) internal virtual returns (bool) {
        if (!hasRole(role, account)) {
            _roles[role].hasRole[account] = true;
            emit RoleGranted(role, account, _msgSender());
            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Attempts to revoke `role` to `account` and returns a boolean indicating if `role` was revoked.
     *
     * Internal function without access restriction.
     *
     * May emit a {RoleRevoked} event.
     */
    function _revokeRole(bytes32 role, address account) internal virtual returns (bool) {
        if (hasRole(role, account)) {
            _roles[role].hasRole[account] = false;
            emit RoleRevoked(role, account, _msgSender());
            return true;
        } else {
            return false;
        }
    }
}

// File: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.2/contracts/utils/ReentrancyGuard.sol


// OpenZeppelin Contracts (last updated v5.0.0) (utils/ReentrancyGuard.sol)

pragma solidity ^0.8.20;

/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 */
abstract contract ReentrancyGuard {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;

    uint256 private _status;

    /**
     * @dev Unauthorized reentrant call.
     */
    error ReentrancyGuardReentrantCall();

    constructor() {
        _status = NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and making it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() private {
        // On the first call to nonReentrant, _status will be NOT_ENTERED
        if (_status == ENTERED) {
            revert ReentrancyGuardReentrantCall();
        }

        // Any calls to nonReentrant after this point will fail
        _status = ENTERED;
    }

    function _nonReentrantAfter() private {
        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _status = NOT_ENTERED;
    }

    /**
     * @dev Returns true if the reentrancy guard is currently set to "entered", which indicates there is a
     * `nonReentrant` function in the call stack.
     */
    function _reentrancyGuardEntered() internal view returns (bool) {
        return _status == ENTERED;
    }
}

// File: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.2/contracts/token/ERC20/IERC20.sol


// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC20/IERC20.sol)

pragma solidity ^0.8.20;

/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
 */
interface IERC20 {
    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /**
     * @dev Returns the value of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the value of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves a `value` amount of tokens from the caller's account to `to`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address to, uint256 value) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the
     * caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 value) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to` using the
     * allowance mechanism. `value` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

// File: @chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol


pragma solidity ^0.8.0;

interface AggregatorV3Interface {
  function decimals() external view returns (uint8);

  function description() external view returns (string memory);

  function version() external view returns (uint256);

  function getRoundData(
    uint80 _roundId
  ) external view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);

  function latestRoundData()
    external
    view
    returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}

// File: src/KipuBankV2.sol


pragma solidity ^0.8.24;





// @dev Interface for the optional metadata functions of the ERC20 standard.
interface IERC20Metadata is IERC20 {
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);
}
/// @title KipuBankV2
/// @author pera-h
contract KipuBankV2 is AccessControl, ReentrancyGuard {
    /// @notice roles for access control
    bytes32 public constant OPERATIONS_MANAGER_ROLE = keccak256("OPERATIONS_MANAGER_ROLE");
    bytes32 public constant ASSET_MANAGER_ROLE = keccak256("ASSET_MANAGER_ROLE");
    bytes32 public constant FUNDS_RECOVERY_ROLE = keccak256("FUNDS_RECOVERY_ROLE");

    /// @notice statevariables

    /// @notice The maximum total value of all assets the bank can hold, in USD with 8 decimals.
    uint256 public bankCapInUsd;

    /// @notice The maximum value a user can withdraw in a single transaction, in USD with 8 decimals.
    uint256 public withdrawalLimitInUsd;
    
    /// @notice The current total value of all assets held by the bank, in USD with 8 decimals.
    uint256 public totalBankValueInUsd;

    /// @notice Mapping from token address to user address to the user's balance.
    mapping(address => mapping(address => uint256)) public balances;
    
    /// @notice Mapping from a supported token address to its Chainlink price feed address.
    mapping(address => address) public tokenPriceFeeds;

    /// @notice A constant to represent native Ether, following the EIP-7528
    address public constant ETH_ADDRESS = address(0);

    /// @notice Events
    event Deposit(address indexed user, address indexed token, uint256 amount);
    event Withdrawal(address indexed user, address indexed token, uint256 amount);
    event TokenAdded(address indexed token, address indexed priceFeed);
    event BankCapUpdated(uint256 newCapInUsd);
    event WithdrawalLimitUpdated(uint256 newLimitInUsd);
    event BalanceRecovered(address indexed admin, address indexed user, address indexed token, uint256 newBalance);
    
    /// @notice errors
    error TokenNotSupported(address token);
    error InvalidAmount();
    error InsufficientBalance(uint256 balance, uint256 requested);
    error TransferFailed();
    error MsgValueMustBeZeroForErc20();
    error AmountDoesNotMatchMsgValue();
    error WithdrawalAmountExceedsUsdLimit(uint256 amountInUsd, uint256 limitInUsd);
    error BankCapExceeded(uint256 currentTotalValue, uint256 depositValue, uint256 bankCap);
    error InvalidPriceFeed(address token);

    /// @notice constructor, grant all important roles to admin
    constructor(uint256 _initialBankCapInUsd, uint256 _initialWithdrawalLimitInUsd) {
        bankCapInUsd = _initialBankCapInUsd;
        withdrawalLimitInUsd = _initialWithdrawalLimitInUsd;

        // Grant all roles to the deployer.
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATIONS_MANAGER_ROLE, msg.sender);
        _grantRole(ASSET_MANAGER_ROLE, msg.sender);
        _grantRole(FUNDS_RECOVERY_ROLE, msg.sender);
    }

    /// @notice Rules-related functions

    /// @notice Updates the total bank value cap.
    function setBankCapInUsd(uint256 _newCap) external onlyRole(OPERATIONS_MANAGER_ROLE) {
        bankCapInUsd = _newCap;
        emit BankCapUpdated(_newCap);
    }

    /// @notice Updates the per-transaction withdrawal limit.
    function setWithdrawalLimitInUsd(uint256 _newLimit) external onlyRole(OPERATIONS_MANAGER_ROLE) {
        withdrawalLimitInUsd = _newLimit;
        emit WithdrawalLimitUpdated(_newLimit);
    }

    /// @notice Adds a new token to the list of supported assets by providing its price feed.
    function addToken(address _tokenAddress, address _priceFeedAddress) external onlyRole(ASSET_MANAGER_ROLE) {
        if (_priceFeedAddress == address(0)) revert InvalidAmount();
        tokenPriceFeeds[_tokenAddress] = _priceFeedAddress;
        emit TokenAdded(_tokenAddress, _priceFeedAddress);
    }

    /// @notice Manually adjusts a user's balance for recovery purposes.
    function recoverBalance(address _tokenAddress, address _user, uint256 _newBalance) external onlyRole(FUNDS_RECOVERY_ROLE) {
        uint256 oldBalance = balances[_tokenAddress][_user];

        if (_newBalance > oldBalance) {
            uint256 diff = _newBalance - oldBalance;
            uint256 valueDiffInUsd = _getValueInUsd(_tokenAddress, diff);
            totalBankValueInUsd += valueDiffInUsd;
        } 

        else if (_newBalance < oldBalance) {
            uint256 diff = oldBalance - _newBalance;
            uint256 valueDiffInUsd = _getValueInUsd(_tokenAddress, diff);
            totalBankValueInUsd -= valueDiffInUsd;
        }

        balances[_tokenAddress][_user] = _newBalance;
        emit BalanceRecovered(msg.sender, _user, _tokenAddress, _newBalance);
    }

    /// @notice deposit and withdrawal multi-token

    /// @notice Deposits ETH or a supported ERC20 token into the bank.
    function deposit(address _tokenAddress, uint256 _amount) external payable nonReentrant {
        if (_amount == 0) revert InvalidAmount();
        
        if (_tokenAddress != ETH_ADDRESS && tokenPriceFeeds[_tokenAddress] == address(0)) {
            revert TokenNotSupported(_tokenAddress);
        }

        // Check if the deposit would exceed the bank's total value cap.
        uint256 depositValueInUsd = _getValueInUsd(_tokenAddress, _amount);
        if (totalBankValueInUsd + depositValueInUsd > bankCapInUsd) {
            revert BankCapExceeded(totalBankValueInUsd, depositValueInUsd, bankCapInUsd);
        }

        if (_tokenAddress == ETH_ADDRESS) {
            if (msg.value != _amount) revert AmountDoesNotMatchMsgValue();
        } else {
            if (msg.value > 0) revert MsgValueMustBeZeroForErc20();
            bool success = IERC20(_tokenAddress).transferFrom(msg.sender, address(this), _amount);
            if (!success) revert TransferFailed();
        }

        balances[_tokenAddress][msg.sender] += _amount;
        
        totalBankValueInUsd += depositValueInUsd;


        emit Deposit(msg.sender, _tokenAddress, _amount);
    }

    /// @notice Withdraws ETH or a supported ERC20 token from the bank.
    function withdraw(address _tokenAddress, uint256 _amount) external nonReentrant {
        if (_amount == 0) revert InvalidAmount();
        uint256 userBalance = balances[_tokenAddress][msg.sender];
        if (userBalance < _amount) revert InsufficientBalance(userBalance, _amount);

        uint256 amountInUsd = _getValueInUsd(_tokenAddress, _amount);
        if (amountInUsd > withdrawalLimitInUsd) {
            revert WithdrawalAmountExceedsUsdLimit(amountInUsd, withdrawalLimitInUsd);
        }

        balances[_tokenAddress][msg.sender] -= _amount;

        totalBankValueInUsd -= amountInUsd;

        if (_tokenAddress == ETH_ADDRESS) {
            (bool success, ) = msg.sender.call{value: _amount}("");
            if (!success) revert TransferFailed();
        } else {
            bool success = IERC20(_tokenAddress).transfer(msg.sender, _amount);
            if (!success) revert TransferFailed();
        }

        emit Withdrawal(msg.sender, _tokenAddress, _amount);
    }

    /// @notice internal helper functions

    /// @notice (Internal) Fetches the token price and normalizes it to 8 decimals.
    function _getPriceUsd8(address _tokenAddress) internal view returns (uint256 price8) {
        address feedAddr = tokenPriceFeeds[_tokenAddress];
        if (feedAddr == address(0)) revert TokenNotSupported(_tokenAddress);

        AggregatorV3Interface feed = AggregatorV3Interface(feedAddr);
        (, int256 answer,,,) = feed.latestRoundData();
        if (answer <= 0) revert InvalidPriceFeed(_tokenAddress);

        uint8 pdec = feed.decimals();
        uint256 u = uint256(answer);
        if (pdec > 8)       price8 = u / (10 ** (pdec - 8));
        else if (pdec < 8)  price8 = u * (10 ** (8 - pdec));
        else                price8 = u;
    }

    /// @notice (Internal) Gets the number of decimals for a given token.
    function _getTokenDecimals(address _tokenAddress) internal view returns (uint8) {
        if (_tokenAddress == ETH_ADDRESS) return 18;
        return IERC20Metadata(_tokenAddress).decimals();
    }

    /// @notice (Internal) Calculates the USD value of a given amount of a token.
    function _getValueInUsd(address _tokenAddress, uint256 _amount) internal view returns (uint256) {
        if (_amount == 0) return 0;
        uint256 price8 = _getPriceUsd8(_tokenAddress);
        uint8 tdec = _getTokenDecimals(_tokenAddress); 
        
        return (_amount * price8) / (10 ** uint256(tdec));
    }
}