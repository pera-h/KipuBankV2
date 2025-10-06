// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.2/contracts/access/AccessControl.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.2/contracts/utils/ReentrancyGuard.sol";

contract KipuBankV2 is AccessControl, ReentrancyGuard {
    // ROLES DEFINITION
    
    /// @notice Manages the bankCap and withdrawalLimit
    bytes32 public constant OPS_MANAGER_ROLE = keccak256("OPS_MANAGER_ROLE");


    // STATE VARIABLES 

    /// @notice The maximum amount of ETH a user can withdraw in a single transaction, can be changed by the OPSManager.
    uint256 public withdrawalLimit;

    /// @notice The maximum total amount of ETH that can be deposited into the entire bank, can be changed by the OPSManager.
    uint256 public  bankCap;

    /// @notice Maps a user's address to their balance in the bank.
    // mapping(address => mapping(address => uint256)) public balances;
    mapping(address => uint256) public balances;
    mapping(address => address) public tokenPriceFeeds;

    /// @notice The total amount of ETH currently held by the contract.
    uint256 public totalSupply;

    /// @notice The total number of successful deposits.
    uint256 public depositCount;

    /// @notice The total number of successful withdrawals.
    uint256 public withdrawalCount;

    // EVENTS

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    event CapsUpdated(uint256 bankCap, uint256 withdrawalLimit);

    // ERRORS

    error DepositAmountIsZero();
    error BankCapExceeded(uint256 cap, uint256 attemptedTotal);
    error WithdrawAmountIsZero();
    error WithdrawalExceedsLimit(uint256 requested, uint256 limit);
    error InsufficientBalance(uint256 balance, uint256 requested);
    error TransferFailed();
    error Reentrancy();

    // MODIFIER


    modifier whenDepositAllowed(uint256 _amount) {
        if (_amount == 0) revert DepositAmountIsZero();
        uint256 attemptedTotal = totalSupply + _amount;
        if (attemptedTotal > bankCap) revert BankCapExceeded(bankCap, attemptedTotal);
        _;
    }
    // CONSTRUCTOR

    constructor(uint256 _initialBankCap, uint256 _initialWithdrawalLimit, address admin) {
        if (_initialBankCap == 0 || _initialWithdrawalLimit == 0) revert();
        bankCap = _initialBankCap;
        withdrawalLimit = _initialWithdrawalLimit;
        
        // Set admin
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPS_MANAGER_ROLE, admin);
    }

    ///OPS_MANAGER setCaps function
    function setCaps(uint256 _bankCap, uint256 _withdrawalLimit) external onlyRole(OPS_MANAGER_ROLE)
    {
        bankCap = _bankCap;
        withdrawalLimit = _withdrawalLimit;
        emit CapsUpdated(_bankCap, _withdrawalLimit);
    }

    // EXTERNAL FUNCTIONS

    /// @notice Allows a user to deposit ETH into their account.
    function deposit() external payable nonReentrant whenDepositAllowed(msg.value) {
        // Effects
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
        ++depositCount;

        // Emit event
        emit Deposit(msg.sender, msg.value);
    }

    /// @notice Allows a user to withdraw a specified amount of ETH from their account.
    function withdraw(uint256 _amount) external nonReentrant {
        // Checks
        if (_amount == 0) {
            revert WithdrawAmountIsZero();
        }
        if (_amount > withdrawalLimit) {
            revert WithdrawalExceedsLimit(_amount, withdrawalLimit);
        }
        uint256 userBalance = balances[msg.sender];
        if (_amount > userBalance) {
            revert InsufficientBalance(userBalance, _amount);
        }

        // Effects - State changes happen before external call
        balances[msg.sender] = userBalance - _amount;
        totalSupply -= _amount;
        ++withdrawalCount;
    
        // Emit event before external call as a good practice
        emit Withdrawal(msg.sender, _amount);

        // Interaction
        (bool success, ) = msg.sender.call{value: _amount}("");
        if (!success) {
            revert TransferFailed();
        }
    }

    // VIEW FUNCTIONS

    /// @notice Returns aggregated bank stats in one call.
    function getBankStats() external view returns (
        uint256 cap,
        uint256 perTxLimit,
        uint256 total,
        uint256 dCount,
        uint256 wCount
    ) {
        return (bankCap, withdrawalLimit, totalSupply, depositCount, withdrawalCount);
    }

    receive() external payable { revert("Use deposit()"); }
}
