import os
import requests
import hashlib
from dotenv import load_dotenv
import ecdsa
import base58
import time
import sys

# Load environment variables from .env file
load_dotenv()

# TronGrid API configuration
TRONGRID_API_BASE_URL = "https://api.trongrid.io/v1"
TRONGRID_API_KEY = os.getenv("TRONGRID_API_KEY")

# USDT-TRC20 contract address
USDT_CONTRACT_ADDRESS = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

# --- Tron Address Utilities ---

def generate_tron_address():
    """Generate a new Tron key pair and return the address."""
    # Generate private key (32 bytes)
    private_key_bytes = os.urandom(32)
    private_key_hex = private_key_bytes.hex()

    # Create SECP256k1 curve
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()

    # Get public key (without 04 prefix)
    public_key = vk.to_string()

    # Step 1: SHA256 hash of public key
    public_key_sha256 = hashlib.sha256(public_key).digest()

    # Step 2: RIPEMD160 hash of SHA256 result
    public_key_ripemd160 = hashlib.new('ripemd160', public_key_sha256).digest()

    # Step 3: Add Tron prefix (0x41)
    address_prefix = b'\x41'
    address_bytes = address_prefix + public_key_ripemd160

    # Step 4: Calculate checksum (double SHA256)
    checksum = hashlib.sha256(hashlib.sha256(address_bytes).digest()).digest()[:4]

    # Step 5: Add checksum to address
    address_with_checksum = address_bytes + checksum

    # Step 6: Encode in Base58
    tron_address = base58.b58encode(address_with_checksum).decode('utf-8')

    # WARNING: Only the address is needed to receive payments.
    # The private key should NEVER be shared with customers!
    # Store the private key securely if you plan to send from this address.
    return {"address": tron_address, "private_key": private_key_hex}

# --- TronGrid API Functions ---

def make_trongrid_request(endpoint, params=None):
    """Make a GET request to TronGrid API."""
    url = f"{TRONGRID_API_BASE_URL}{endpoint}"
    headers = {}
    if TRONGRID_API_KEY:
        headers["TRON-PRO-API-KEY"] = TRONGRID_API_KEY

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()  # Raises exception for HTTP errors (4xx or 5xx)
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error making TronGrid API request: {e}")
        return None

def get_usdt_balance(address):
    """Get USDT balance for specified address using TronGrid API."""
    # Use account information endpoint
    account_info = make_trongrid_request(f"/accounts/{address}")
    if not account_info:
        return None

    # Find USDT balance (token with ID USDT_CONTRACT_ADDRESS)
    usdt_balance = None
    for token in account_info.get("trc20", []):
        # The key in trc20 dictionary is the token contract address
        if USDT_CONTRACT_ADDRESS in token:
            # Balance is in "sun", need to divide by 10^6 for USDT
            try:
                balance_sun = int(token[USDT_CONTRACT_ADDRESS])
                # For precision, it's better to know the token decimals.
                # Could get from token info via TronGrid API, but USDT uses 6.
                balance_usdt = balance_sun / (10**6)
                usdt_balance = balance_usdt
                break  # Found USDT balance, exit loop
            except ValueError:
                print(f"Error converting USDT balance: {token[USDT_CONTRACT_ADDRESS]}")
                return None

    if usdt_balance is None:
        return 0.0  # If USDT not found on account, balance is 0

    return usdt_balance

def monitor_address_for_usdt(address):
    """Monitor incoming USDT transactions to specified address using TronGrid API."""
    print(f"Monitoring incoming USDT to address: {address}")
    print("Press Ctrl+C to stop.")

    # For reliable monitoring, we periodically check transaction history
    # for transactions with USDT contract as sender and our address as recipient
    
    last_timestamp = 0  # Track last processed transaction timestamp

    while True:
        try:
            params = {
                "only_confirmed": True,
                "order_by": "block_timestamp,desc",
                "limit": 50  # Configurable
            }
            transactions_data = make_trongrid_request(f"/accounts/{address}/transactions", params=params)

            if transactions_data and transactions_data.get("data"):
                transactions = transactions_data["data"]
                new_transactions = []
                
                # Process transactions starting with newest
                for tx in transactions:
                    tx_timestamp = tx.get("block_timestamp", 0)
                    if tx_timestamp > last_timestamp:
                        new_transactions.append(tx)
                    else:
                        # Transaction already processed, stop
                        break

                # Process new transactions in reverse order (oldest to newest)
                for tx in reversed(new_transactions):
                    tx_id = tx.get("txID")
                    tx_timestamp = tx.get("block_timestamp")
                    contract_data = tx.get("raw_data", {}).get("contract", [])

                    if contract_data:
                        contract_type = contract_data[0].get("type")
                        parameter = contract_data[0].get("parameter", {}).get("value", {})

                        # Check if this is a TRC20 contract call (TRIGGER_SMART_CONTRACT)
                        if contract_type == "TriggerSmartContract":
                            contract_address_called = parameter.get("contract_address")
                            # Check if USDT contract was called
                            if contract_address_called == USDT_CONTRACT_ADDRESS:
                                # Check if this is a transfer function
                                data = parameter.get("data")
                                if data and data.startswith("a9059cbb"):  # transfer function selector
                                    # Decode transaction data
                                    # This requires more complex parsing of hex string data
                                    # data: a9059cbb + 64 bytes recipient address (with padding) + 64 bytes amount (with padding)
                                    try:
                                        recipient_hex = data[10:74]
                                        amount_hex = data[74:138]

                                        # Convert hex to bytes and remove leading zeros
                                        recipient_bytes = bytes.fromhex(recipient_hex)
                                        # Address in Tron format (with 41 prefix)
                                        recipient_address_bytes = b'\x41' + recipient_bytes[-20:]
                                        recipient_address_tron = base58.b58encode(recipient_address_bytes).decode('utf-8')

                                        # Convert hex to integer (amount in sun)
                                        amount_sun = int(amount_hex, 16)
                                        amount_usdt = amount_sun / (10**6)  # USDT has 6 decimals

                                        # Verify transaction was sent to our address
                                        if recipient_address_tron == address:
                                            print(f"\n--- Incoming USDT Payment ---")
                                            print(f"Transaction ID: {tx_id}")
                                            print(f"Amount: {amount_usdt} USDT")
                                            print(f"Time: {tx_timestamp}")
                                            # Add notification or payment processing logic here

                                    except Exception as e:
                                        print(f"Error parsing transaction data {tx_id}: {e}")

                # Update last processed timestamp
                if new_transactions:
                    last_timestamp = new_transactions[0].get("block_timestamp", last_timestamp)

            # Wait before next request
            time.sleep(10)  # Check every 10 seconds (configurable)

        except KeyboardInterrupt:
            print("\nMonitoring stopped by user.")
            break
        except Exception as e:
            print(f"Error during monitoring: {e}")
            time.sleep(30)  # Wait longer on error

# --- Command Line Interface ---

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python usdt_receiver_api.py [generate_address] [get_balance <address>] [monitor <address>]")
        sys.exit(1)

    command = sys.argv[1]

    if command == "generate_address":
        keys = generate_tron_address()
        print(f"Generated new TRC20 address: {keys['address']}")
        print(f"Private key (keep VERY secure if needed for sending): {keys['private_key']}")
        print("Provide the address to your customer.")
        print("WARNING: Private key is shown for example. In production, it should be stored more securely.")

    elif command == "get_balance":
        if len(sys.argv) != 3:
            print("Usage: python usdt_receiver_api.py get_balance <address>")
            sys.exit(1)
        address_to_check = sys.argv[2]
        balance = get_usdt_balance(address_to_check)
        if balance is not None:
            print(f"USDT balance for address {address_to_check}: {balance}")

    elif command == "monitor":
        if len(sys.argv) != 3:
            print("Usage: python usdt_receiver_api.py monitor <address>")
            sys.exit(1)
        address_to_monitor = sys.argv[2]
        monitor_address_for_usdt(address_to_monitor)

    else:
        print("Unknown command.")
        print("Usage: python usdt_receiver_api.py [generate_address] [get_balance <address>] [monitor <address>]")
