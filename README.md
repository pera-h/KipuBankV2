# KipuBankV2

contract creation Address: https://sepolia.etherscan.io/tx/0x6e158f9f5af53300751a8e510f273ab6f8ee4f64c7587be47d730546276703dd
# KipuBankV2: An Advanced Multi-Token Smart Contract Bank

## Introduction

The primary goal of this project is to demonstrate the application of advanced Solidity patterns, security best practices, and integration with external data sources to build a contract that is both feature-rich and secure.

---

## Key Features & Improvements

This contract introduces several critical improvements over a standard banking contract, focusing on creating a secure and versatile DeFi primitive.

### 1. Role-Based Access Control
 The contract implements OpenZeppelin's `AccessControl` to establish distinct administrative roles: `OPERATIONS_MANAGER` (for managing limits), `ASSET_MANAGER` (for listing new tokens), and `FUNDS_RECOVERY` (for emergency balance corrections).

### 2. Multi-Token & Native Asset Support
The bank's accounting system is designed to handle both native ETH and any ERC20-compliant token. The contract uses the `address(0)` convention to represent ETH, aligning with industry standards.

### 3. USD-Denominated Risk Management (Chainlink Integration)
The contract integrates with Chainlink Price Feeds to enforce two key risk parameters denominated in U.S. Dollars:
    - Bank Cap: A maximum total value (TVL) of all assets the contract can hold.
    - Withdrawal Limit: A per-transaction limit on the value a user can withdraw.

### 4. Enhanced Security Patterns
The contract is fortified with multiple security enhancements:
    - Reentrancy Guard: Uses OpenZeppelin's `ReentrancyGuard` on all state-changing external-facing functions (`deposit`, `withdraw`).
    - Checks-Effects-Interactions Pattern: State changes (e.g., updating balances) are made before external calls (token transfers) to mitigate reentrancy risks.
    - Robust Oracle Handling: The contract validates that oracle prices are positive (`> 0`) and dynamically normalizes prices from different decimal precisions to a consistent internal standard.

---

## Deployment and Interaction Instructions

This contract was developed and tested using the **Remix IDE** and can be deployed directly from your browser.

### Prerequisites
1.  A browser with the [MetaMask](https://metamask.io/) extension installed.
2.  Sepolia testnet ETH in your MetaMask wallet to cover gas fees. You can get testnet ETH from a [faucet](https://cloud.google.com/application/web3/faucet/ethereum/sepolia/).

### Deployment using Remix IDE
1.  **Open Remix:** Navigate to [remix.ethereum.org](https://remix.ethereum.org/).
2.  **Create File:** Create a new file named `KipuBankV2.sol` and paste the contract's source code.
3.  **Compile:**
    * Go to the "Solidity Compiler" tab.
    * Select compiler version **`0.8.30`**.
    * Click "Compile KipuBankV2.sol". A green checkmark will appear.
4.  **Deploy:**
    * Go to the "Deploy & Run Transactions" tab.
    * Set the "ENVIRONMENT" to **"Injected Provider - MetaMask"**. Your wallet will connect.
    * In the "Deploy" section, provide the constructor arguments:
        * `_initialBankCapInUsd`: e.g., `500000000000` (for a $5,000 cap with 8 decimals).
        * `_initialWithdrawalLimitInUsd`: e.g., `100000000000` (for a $1,000 limit with 8 decimals).
    * Click "Deploy" and confirm the transaction in MetaMask.
5.  **Verify on Etherscan:** Follow the contract verification process on Sepolia Etherscan using the "flattened" source code from Remix and the exact compiler version (`0.8.30`).

### Interaction
* **Admin:** After deployment, the admin must call `addToken` to list supported assets. For ETH, use `0x00...00` as the token address and the Sepolia ETH/USD oracle address (`0x694AA1769357215DE4FAC081bf1f309aDC325306`).
* **Users:**
    * To **deposit ETH**, call the `deposit` function with `_tokenAddress` as `0x00...00` and send ETH in the `value` field.
    * To **deposit an ERC20 token**, first `approve` the contract to spend your tokens, then call `deposit`.
    * To **withdraw**, call the `withdraw` function with the token address and desired amount.

---

## Design Decisions & Trade-offs

* **Oracle Price Normalization:** All prices fetched from Chainlink are normalized to a standard **8 decimal places** internally. This simplifies value calculations and provides a consistent USD representation throughout the contract. The trade-off is the minor gas cost of normalization if a price feed does not use 8 decimals natively.

* **`totalBankValueInUsd` Calculation:** The bank's total value is updated only upon `deposit`, `withdraw`, and `recoverBalance` events. It does **not** fluctuate in real-time with the market prices of the held assets. This is a crucial gas-saving measure, as continuously re-evaluating the entire portfolio would be prohibitively expensive. This value should be interpreted as an accurate accounting of the bank's worth at the time of its last state change.

* **`recoverBalance` Function:** This function provides a powerful administrative capability for fund recovery. It represents a centralization trade-off for the sake of operational security and user support. In a production environment, this function should be controlled by a secure multi-signature wallet or a decentralized governance process. The `BalanceRecovered` event ensures all such administrative actions are transparent and auditable on-chain.

---

## Deployed Contract on Sepolia Testnet

* **Contract Address:** `0xdabd34dC8a9F850dDa578041C3A72e8f20CA6B8E`
* **Etherscan Link:** `https://sepolia.etherscan.io/address/0xdabd34dc8a9f850dda578041c3a72e8f20ca6b8e#code`