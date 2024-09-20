#IMPORTS
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

#GLOBAL VARIABLES
encrypted_messages = []
signature_signed_messages = []

##FUNCTION CALL: GENERATE RSA KEYS
def generate_rsa_keys():
    if not os.path.exists('private_key.pem') or not os.path.exists('public_key.pem'):
        # Generate RSA private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Generate RSA public key
        public_key = private_key.public_key()

        # Serialize private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Serialize public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Save the private key to a file
        with open('private_key.pem', 'wb') as f:
            f.write(private_pem)

        # Save the public key to a file
        with open('public_key.pem', 'wb') as f:
            f.write(public_pem)

        print("RSA keys have been generated successfully!")
    else:
        print("RSA keys already exist.")

def sign_message(message: str):
    # Load the private key
    private_key = load_private_key()

    # Sign the message
    signature = private_key.sign(
        message.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    # Append the signed message to the list
    signature_signed_messages.append((message, signature))
    print("Message signed and sent.")

def verify_signature(signature: bytes, message: str) -> bool:
    # Load the public key
    public_key = load_public_key()
    try:
        # Verify the signature
        public_key.verify(
            signature,
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            # Use SHA-256 hash algorithm
            hashes.SHA256()
        )
        print("Signature is valid")
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

def load_public_key():
    # Load the public key
    with open('public_key.pem', 'rb') as f:
        # Uses the default backend
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

    # Return the public key
    return public_key

def load_private_key():
    # Load the private key
    with open('private_key.pem', 'rb') as f:
        # Uses the default backend
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    # Return the private key
    return private_key

def rsa_encrypt(message):
    # Load the public key
    public_key = load_public_key()
    # Encrypt the message
    encrypted_message = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            # Use SHA-256 hash algorithm
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Append the encrypted message to the list
    encrypted_messages.append((encrypted_message, len(message)))

def load_signed_messages():
    # Check if there are any signed messages
    if not signature_signed_messages:
        print("No signed messages available.")
        return

    # Display the signed messages
    print("The following messages are available:")
    for idx, (msg, _) in enumerate(signature_signed_messages):
        print(f"\t{idx + 1}: {msg}")
    print(">> ", end="")
    msg_choice = int(input())

    # Check if the user's choice is valid
    if msg_choice in range(1, len(signature_signed_messages) + 1):
        message, signature = signature_signed_messages[msg_choice - 1]
        verify_signature(signature, message)
    pass

def load_encrypted_messages():
    # Check if there are any encrypted messages
    if not encrypted_messages:
        print("No encrypted messages available.")
        return

    # Display the encrypted messages
    print("The following messages are available:")
    for idx, (encrypted_message, original_length) in enumerate(encrypted_messages):
        print(f"\t{idx + 1}: (length = {original_length})")
    print(">> ", end="")
    user_choice = int(input())

    # Check if the user's choice is valid
    if user_choice in range(1, len(encrypted_messages) + 1):
        encrypted_message = rsa_decrypt(encrypted_messages[user_choice - 1][0])
        print(f"The decrypted message is: {encrypted_message}")


def rsa_decrypt(encrypted_message):
    # Load the private key
    private_key = load_private_key()
    # Decrypt the message
    decrypted_message = private_key.decrypt(
        encrypted_message,
        # Use OAEP padding
        padding.OAEP(
            # Use SHA-256 hash algorithm
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Return the decrypted message
    return decrypted_message.decode('utf-8')

def show_current_keys():
    with open('public_key.pem', 'rb') as f:
        public_key = f.read()
    with open('private_key.pem', 'rb') as f:
        private_key = f.read()

    # Print the keys
    print(f"Public key: {public_key}")
    print(f"Private key: {private_key}")

def menu():
    while True:
        try:
            print("Please select your user type:\n\t1. Public user\n\t2. Owner\n\t3. Quit")
            print(">> ", end="")
            user_type = int(input())
            if user_type in [1, 2, 3]:
                if user_type == 3:
                    print("Goodbye!")
                    break
                elif user_type == 1:
                    while True:
                        try:
                            print("What would you like to do?\n\t1. Send an encrypted message\n\t2. Authenticate a digital signature\n\t3. Back")
                            print(">> ", end="")
                            user_choice = int(input())
                            if user_choice in [1, 2, 3]:
                                if user_choice == 1:
                                    print("Enter the message you would like to send:")
                                    print(">> ", end="")
                                    message = input()
                                    rsa_encrypt(message)
                                elif user_choice == 2:
                                    load_signed_messages()
                                elif user_choice == 3:
                                    break
                            else:
                                print("Invalid selection. Please enter a number between 1 and 3.")
                        except ValueError:
                            print("Invalid input. Please enter a valid number.")
                elif user_type == 2:
                    while True:
                        try:
                            print("What would you like to do?")
                            print("\t1. Decrypt a received message\n\t2. Digitally sign a message\n\t3. Show the keys\n\t4. Generate new keys\n\t5. Back")
                            print(">> ", end="")
                            user_choice = int(input())
                            if user_choice in [1, 2, 3, 4, 5]:
                                if user_choice == 1:
                                    load_encrypted_messages()
                                elif user_choice == 2:
                                    print("Enter a message:")
                                    print(">> ", end="")
                                    message = input()
                                    sign_message(message)
                                    pass
                                elif user_choice == 3:
                                    # Method call to show keys
                                    show_current_keys()
                                    pass
                                elif user_choice == 4:
                                    # Delete existing PEM files if they exist
                                    if os.path.exists('private_key.pem'):
                                        os.remove('private_key.pem')
                                    if os.path.exists('public_key.pem'):
                                        os.remove('public_key.pem')
                                    print("RSA keys have been deleted.")
                                    generate_rsa_keys()
                                elif user_choice == 5:
                                    break
                            else:
                                print("Invalid selection. Please enter a number between 1 and 5.")
                        except ValueError:
                            print("Invalid input. Please enter a valid number.")
            else:
                print("Invalid selection. Please enter a number between 1 and 3.")
        except ValueError:
            print("Invalid input. Please enter a valid number.")

if __name__ == '__main__':
    generate_rsa_keys()
    menu()