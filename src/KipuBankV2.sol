// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.2/contracts/access/AccessControl.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.2/contracts/utils/ReentrancyGuard.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.2/contracts/token/ERC20/IERC20.sol";
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";


contract KipuBankV2 is AccessControl, ReentrancyGuard {
    /// @notice roles
    bytes32 public constant OPERATIONS_MANAGER_ROLE = keccak256("OPERATIONS_MANAGER_ROLE");
    bytes32 public constant ASSET_MANAGER_ROLE = keccak256("ASSET_MANAGER_ROLE");

    /// @notice statevariables
    uint256 public bankCapInUsd;
    uint256 public withdrawalLimitInUsd;
    uint256 public totalBankValueInUsd;

    mapping(address => mapping(address => uint256)) public balances;
    mapping(address => address) public tokenPriceFeeds;

    address public constant ETH_ADDRESS = address(0);

    /// @notice Events
    event Deposit(address indexed user, address indexed token, uint256 amount);
    event Withdrawal(address indexed user, address indexed token, uint256 amount);
    event TokenAdded(address indexed token, address indexed priceFeed);
    event BankCapUpdated(uint256 newCapInUsd);
    event WithdrawalLimitUpdated(uint256 newLimitInUsd);

    /// @notice errors
    error TokenNotSupported(address token);
    error InvalidAmount();
    error InsufficientBalance(uint256 balance, uint256 requested);
    error TransferFailed();
    error MsgValueMustBeZeroForErc20();
    error AmountDoesNotMatchMsgValue();

    /// @notice constructor, grant all important roles to admin
    constructor(uint256 _initialBankCapInUsd, uint256 _initialWithdrawalLimitInUsd) {
        bankCapInUsd = _initialBankCapInUsd;
        withdrawalLimitInUsd = _initialWithdrawalLimitInUsd;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATIONS_MANAGER_ROLE, msg.sender);
        _grantRole(ASSET_MANAGER_ROLE, msg.sender);
    }

    /// @notice Rules-related functions
    function setBankCapInUsd(uint256 _newCap) external onlyRole(OPERATIONS_MANAGER_ROLE) {
        bankCapInUsd = _newCap;
        emit BankCapUpdated(_newCap);
    }

    function setWithdrawalLimitInUsd(uint256 _newLimit) external onlyRole(OPERATIONS_MANAGER_ROLE) {
        withdrawalLimitInUsd = _newLimit;
        emit WithdrawalLimitUpdated(_newLimit);
    }

    function addToken(address _tokenAddress, address _priceFeedAddress) external onlyRole(ASSET_MANAGER_ROLE) {
        if (_priceFeedAddress == address(0)) revert InvalidAmount();
        tokenPriceFeeds[_tokenAddress] = _priceFeedAddress;
        emit TokenAdded(_tokenAddress, _priceFeedAddress);
    }

    /// @notice deposit and withdrawal multi-token
    function deposit(address _tokenAddress, uint256 _amount) external payable nonReentrant {
        if (_amount == 0) revert InvalidAmount();

        if (_tokenAddress == ETH_ADDRESS) {
            if (msg.value != _amount) revert AmountDoesNotMatchMsgValue();
        } else {
            if (msg.value > 0) revert MsgValueMustBeZeroForErc20();
            
            bool success = IERC20(_tokenAddress).transferFrom(msg.sender, address(this), _amount);
            if (!success) revert TransferFailed();
        }

        balances[_tokenAddress][msg.sender] += _amount;
        emit Deposit(msg.sender, _tokenAddress, _amount);
    }

    function withdraw(address _tokenAddress, uint256 _amount) external nonReentrant {
        if (_amount == 0) revert InvalidAmount();
        uint256 userBalance = balances[_tokenAddress][msg.sender];
        if (userBalance < _amount) revert InsufficientBalance(userBalance, _amount);

        balances[_tokenAddress][msg.sender] -= _amount;

        if (_tokenAddress == ETH_ADDRESS) {
            (bool success, ) = msg.sender.call{value: _amount}("");
            if (!success) revert TransferFailed();
        } else {
            bool success = IERC20(_tokenAddress).transfer(msg.sender, _amount);
            if (!success) revert TransferFailed();
        }

        emit Withdrawal(msg.sender, _tokenAddress, _amount);
    }
}