# PGP Demonstration

This project demonstrates the core concepts of Pretty Good Privacy (PGP) encryption using Python and the `cryptography` library. It simulates secure messaging between devices (users) with RSA key pairs, message encryption, digital signatures, and authentication.

## Features

- **Key Generation**: Each device generates an RSA key pair (public and private keys).
- **Message Encryption**: Messages are encrypted using the recipient's public key for confidentiality.
- **Digital Signatures**: Messages are signed with the sender's private key for authentication and integrity verification.
- **Secure Communication**: Demonstrates two-way encrypted messaging between devices.
- **Interception Simulation**: Shows how an unauthorized party (Charlie) cannot decrypt messages without the private key.
- **Interactive Mode**: Allows users to send custom messages between devices in real-time.

## How It Works

The `pgp_demo.py` script creates three devices: Alice, Bob, and Charlie. It simulates:

1. **Key Exchange**: Devices generate and share public keys (in a real scenario, this would use key servers).
2. **Message Sending**: Alice sends an encrypted and signed message to Bob, who decrypts and verifies it.
3. **Reply**: Bob replies similarly to Alice.
4. **Interactive Mode**: Users can choose senders and recipients to send custom messages, with interception attempts shown.

The script uses RSA for asymmetric encryption, OAEP padding for encryption, and PSS padding for signatures, with SHA-256 hashing.

## Requirements

- Python 3.x
- `cryptography` library (install via `pip install -r requirements.txt`)

## Running the Demo

1. Clone or download the project.
2. Install dependencies: `pip install -r requirements.txt`
3. Run the script: `python pgp_demo.py`

The script will first run a demonstration, then enter interactive mode where you can send messages by choosing recipients and typing messages. Type 'quit' to exit.

## Security Notes

This is a simplified demonstration for educational purposes. Real PGP implementations include additional features like key management, compression, and integration with email clients. Always use established PGP tools for actual secure communication.
