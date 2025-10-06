// SPDX-License-Identifier: MIT
pragma solidity >=0.8.2 <0.9.0;

/**
 * @title KipuBank
 * @author Seu Nome
 * @notice Um contrato de banco simples e seguro para depositar e sacar ETH.
 */
contract KipuBank {
    // STATE VARIABLES

    /// @notice The maximum amount of ETH a user can withdraw in a single transaction.
    uint256 public immutable withdrawalLimit;

    /// @notice The maximum total amount of ETH that can be deposited into the entire bank.
    uint256 public immutable bankCap;

    /// @notice Maps a user's address to their balance in the bank.
    mapping(address => uint256) public balances;

    /// @notice The total amount of ETH currently held by the contract.
    uint256 public totalSupply;

    /// @notice The total number of successful deposits.
    uint256 public depositCount;

    /// @notice The total number of successful withdrawals.
    uint256 public withdrawalCount;

    // EVENTS

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    // ERRORS

    error DepositAmountIsZero();
    error BankCapExceeded(uint256 cap, uint256 attemptedTotal);
    error WithdrawAmountIsZero();
    error WithdrawalExceedsLimit(uint256 requested, uint256 limit);
    error InsufficientBalance(uint256 balance, uint256 requested);
    error TransferFailed();
    error Reentrancy();

    // MODIFIER

    uint256 private _locked; // 0 = unlocked, 1 = locked
    modifier nonReentrant() {
        if (_locked == 1) revert Reentrancy();
            _locked = 1;
        _;
            _locked = 0;
    }

    modifier whenDepositAllowed(uint256 _amount) {
        if (_amount == 0) revert DepositAmountIsZero();
        uint256 attemptedTotal = totalSupply + _amount;
        if (attemptedTotal > bankCap) revert BankCapExceeded(bankCap, attemptedTotal);
        _;
    }

    // CONSTRUCTOR

    constructor(uint256 _initialBankCap, uint256 _initialWithdrawalLimit) {
        bankCap = _initialBankCap;
        withdrawalLimit = _initialWithdrawalLimit;
        _locked = 0; // Explicitly set unlocked state
    }

    // EXTERNAL FUNCTIONS

    /// @notice Allows a user to deposit ETH into their account.
    function deposit() external payable nonReentrant whenDepositAllowed(msg.value) {
        // Effects
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
        depositCount++;

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
        withdrawalCount++;
    
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
}
