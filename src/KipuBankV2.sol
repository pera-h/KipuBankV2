// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.2/contracts/access/AccessControl.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.2/contracts/utils/ReentrancyGuard.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.2/contracts/token/ERC20/IERC20.sol";
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

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