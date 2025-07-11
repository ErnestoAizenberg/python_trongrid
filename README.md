# USDT-TRC20 Payment Receiver

A Python script for generating Tron (TRX) addresses, checking USDT-TRC20 balances, and monitoring incoming USDT-TRC20 payments using the TronGrid API.

## Features

- Generate new Tron addresses (with private keys)
- Check USDT-TRC20 balance for any Tron address
- Monitor an address for incoming USDT-TRC20 payments in real-time
- Secure handling of private keys
- Easy-to-use command line interface

## Prerequisites

- Python 3.8+
- TronGrid API key (free tier available)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/ErnestoAizenberg/python_trongrid.git
cd python_trongrid
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create a `.env` file in the project directory and add your TronGrid API key:
```env
TRONGRID_API_KEY=your_api_key_here
```

## Usage

### Generate a new Tron address
```bash
python usdt_receiver_api.py generate_address
```

### Check USDT balance for an address
```bash
python usdt_receiver_api.py get_balance TRON_ADDRESS_HERE
```

### Monitor an address for incoming USDT payments
```bash
python usdt_receiver_api.py monitor TRON_ADDRESS_HERE
```

## Command Line Options

| Command          | Description                                                                 |
|------------------|-----------------------------------------------------------------------------|
| `generate_address` | Generates a new Tron address and private key                                |
| `get_balance`    | Checks the USDT-TRC20 balance for a specific Tron address                  |
| `monitor`        | Continuously monitors a Tron address for incoming USDT-TRC20 payments      |

## Security Notes

1. **Private Keys**: The generated private keys should be stored securely. Anyone with access to a private key can control all funds in that address.
2. **API Keys**: Keep your TronGrid API key secret. Store it in the `.env` file which is ignored by Git.
3. **Environment**: For production use, consider running this in a secure environment with proper access controls.

## Getting a TronGrid API Key

1. Go to [TronGrid](https://www.trongrid.io/)
2. Sign up for a free account
3. Get your API key from the dashboard
4. Add it to your `.env` file

## Rate Limits

The free tier of TronGrid has rate limits. If you need higher throughput, consider upgrading your plan.

## Contributing

Contributions are welcome! Please open an issue or pull request for any improvements.
