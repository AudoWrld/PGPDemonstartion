from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64
import json
from datetime import datetime


class Device:
    """Represents a device/user with PGP capabilities"""

    def __init__(self, name):
        self.name = name
        # Generate RSA key pair (PGP uses RSA for encryption)
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        print(f"[KEY GENERATED] {self.name}: Generated PGP key pair")

    def get_public_key_pem(self):
        """Export public key in PEM format for sharing"""
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem.decode("utf-8")

    def encrypt_message(self, message, recipient_public_key):
        """
        Encrypt a message for a recipient using their public key
        Also signs the message with sender's private key
        """
        print(f"\n[ENCRYPTING] {self.name}: Encrypting message...")

        # Convert message to bytes
        message_bytes = message.encode("utf-8")

        # Sign the message with sender's private key (authentication)
        signature = self.private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )

        # Encrypt the message with recipient's public key (confidentiality)
        encrypted_message = recipient_public_key.encrypt(
            message_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Combine encrypted message and signature
        encrypted_data = {
            "sender": self.name,
            "encrypted_message": base64.b64encode(encrypted_message).decode("utf-8"),
            "signature": base64.b64encode(signature).decode("utf-8"),
            "timestamp": datetime.now().isoformat(),
        }

        print(f"[SUCCESS] {self.name}: Message encrypted and signed")
        return encrypted_data

    def decrypt_message(self, encrypted_data, sender_public_key):
        """
        Decrypt a message using own private key
        Verify signature using sender's public key
        """
        print(
            f"\n[RECEIVING] {self.name}: Receiving encrypted message from {encrypted_data['sender']}..."
        )

        # Decode from base64
        encrypted_message = base64.b64decode(encrypted_data["encrypted_message"])
        signature = base64.b64decode(encrypted_data["signature"])

        # Decrypt the message with recipient's private key
        decrypted_message_bytes = self.private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Verify the signature with sender's public key
        try:
            sender_public_key.verify(
                signature,
                decrypted_message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            print(f"[VERIFIED] {self.name}: Signature verified - message is authentic!")
        except Exception as e:
            print(
                f"[ERROR] {self.name}: Signature verification failed - message may be tampered!"
            )
            return None

        decrypted_message = decrypted_message_bytes.decode("utf-8")
        print(f"[DECRYPTED] {self.name}: Message decrypted successfully")

        return decrypted_message


def print_separator():
    print("\n" + "=" * 70 + "\n")


def main():
    print("PGP Encryption Demo - Secure Messaging Between Two Devices")
    print_separator()

    # Create three devices (Alice, Bob, and Charlie as potential interceptor)
    alice = Device("Alice")
    bob = Device("Bob")
    charlie = Device("Charlie")

    print_separator()
    print("Key Exchange Phase")
    print("In real PGP, users exchange public keys through key servers or directly")
    print_separator()

    # Exchange public keys (in real scenario, this would happen through key servers)
    alice_public_key_pem = alice.get_public_key_pem()
    bob_public_key_pem = bob.get_public_key_pem()
    charlie_public_key_pem = charlie.get_public_key_pem()

    print(f"Alice's Public Key (first 100 chars):\n{alice_public_key_pem[:100]}...\n")
    print(f"Bob's Public Key (first 100 chars):\n{bob_public_key_pem[:100]}...\n")
    print(f"Charlie's Public Key (first 100 chars):\n{charlie_public_key_pem[:100]}...\n")

    # Simulate messaging
    print_separator()
    print("Message Exchange Demonstration")
    print_separator()

    # Alice sends a message to Bob
    message1 = "Hello Bob! This is a secret message encrypted with PGP."
    encrypted_msg1 = alice.encrypt_message(message1, bob.public_key)

    print(f"\nEncrypted Data (truncated):")
    print(f"   Sender: {encrypted_msg1['sender']}")
    print(f"   Encrypted Message: {encrypted_msg1['encrypted_message'][:80]}...")
    print(f"   Signature: {encrypted_msg1['signature'][:80]}...")
    print(f"   Timestamp: {encrypted_msg1['timestamp']}")

    # Bob receives and decrypts the message
    decrypted_msg1 = bob.decrypt_message(encrypted_msg1, alice.public_key)
    print(f"\nDecrypted Message: '{decrypted_msg1}'")

    print_separator()

    # Bob replies to Alice
    message2 = "Hi Alice! I received your secure message. PGP encryption works great!"
    encrypted_msg2 = bob.encrypt_message(message2, alice.public_key)

    print(f"\nEncrypted Data (truncated):")
    print(f"   Sender: {encrypted_msg2['sender']}")
    print(f"   Encrypted Message: {encrypted_msg2['encrypted_message'][:80]}...")

    # Alice receives and decrypts Bob's reply
    decrypted_msg2 = alice.decrypt_message(encrypted_msg2, bob.public_key)
    print(f"\nDecrypted Message: '{decrypted_msg2}'")

    print_separator()
    print("PGP Features Demonstrated:")
    print("   * Key Pair Generation (public/private keys)")
    print("   * Message Encryption (confidentiality)")
    print("   * Digital Signatures (authentication & integrity)")
    print("   * Secure two-way communication")
    print_separator()

    # Interactive mode
    print("\nInteractive Mode - Try sending your own messages!")
    print("(Type 'quit' to exit)")
    print("You can choose the recipient for each message.\n")

    devices = {"alice": alice, "bob": bob, "charlie": charlie}
    current_sender = alice

    while True:
        sender_name = current_sender.name

        # Choose recipient
        while True:
            recipient_choice = input(f"{sender_name}, choose recipient (alice/bob/charlie): ").lower().strip()
            if recipient_choice in devices:
                if devices[recipient_choice] == current_sender:
                    print("You cannot send a message to yourself. Choose another recipient.")
                    continue
                current_receiver = devices[recipient_choice]
                break
            else:
                print("Invalid choice. Please choose alice, bob, or charlie.")

        receiver_name = current_receiver.name

        user_message = input(f"{sender_name} -> {receiver_name}: ")

        if user_message.lower() == "quit":
            print("\nGoodbye! Stay secure!")
            break

        if not user_message:
            continue

        # Encrypt and send
        encrypted = current_sender.encrypt_message(
            user_message, current_receiver.public_key
        )

        # Show encrypted data
        print(f"\nEncrypted Data (truncated):")
        print(f"   Sender: {encrypted['sender']}")
        print(f"   Encrypted Message: {encrypted['encrypted_message'][:80]}...")
        print(f"   Signature: {encrypted['signature'][:80]}...")
        print(f"   Timestamp: {encrypted['timestamp']}")

        # Simulate Charlie attempting to intercept
        print(f"\n[INTERCEPTION ATTEMPT] Charlie tries to intercept the message...")
        try:
            intercepted = charlie.decrypt_message(encrypted, current_sender.public_key)
            print(f"[INTERCEPTION SUCCESS] Charlie intercepted: '{intercepted}'")
        except Exception as e:
            print(f"[INTERCEPTION FAILED] Charlie: Cannot decrypt - does not have {receiver_name}'s private key. Error: {str(e)[:100]}...")

        # Decrypt and display
        decrypted = current_receiver.decrypt_message(
            encrypted, current_sender.public_key
        )
        print(f"\n   [RECEIVED] {receiver_name} received: '{decrypted}'\n")

        # Switch sender and receiver for next message
        current_sender, current_receiver = current_receiver, current_sender


if __name__ == "__main__":
    main()