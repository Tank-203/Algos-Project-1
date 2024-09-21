import random
import os
import hashlib

# GLOBAL VARIABLES
encrypted_messages = []
signature_signed_messages = []
public_key = None
private_key = None

# Function to compute the greatest common divisor
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# Function to compute modular inverse using the Extended Euclidean Algorithm
def mod_inverse(e, phi):
    d_old, d_new = 0, 1
    r_old, r_new = phi, e
    while r_new != 0:
        quotient = r_old // r_new
        d_old, d_new = d_new, d_old - quotient * d_new
        r_old, r_new = r_new, r_old - quotient * r_new
    return d_old % phi

# Function to compute modular exponentiation
def mod_exp(base, exponent, modulus):
    result = 1
    base = base % modulus
    while exponent > 0:
        if (exponent % 2) == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result

# Function to generate RSA key pairs
def generate_keypair(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Or another suitable value like 17
    if gcd(e, phi) != 1:
        raise ValueError("e and phi(n) are not coprime. Choose different primes or a different e.")
    d = mod_inverse(e, phi)
    return ((e, n), (d, n))

def load_public_key():
    with open('public_key.pem', 'r') as f:
        e, n = map(int, f.read().split(','))
    return (e, n)

def load_private_key():
    with open('private_key.pem', 'r') as f:
        d, n = map(int, f.read().split(','))
    return (d, n)

def encrypt(plaintext):
    public_key = load_public_key()
    e, n = public_key
    plaintext_int = int.from_bytes(plaintext.encode(), 'big')
    if plaintext_int >= n:
        raise ValueError("Plaintext is too large for the current RSA key size.")
    ciphertext = mod_exp(plaintext_int, e, n)
    encrypted_messages.append((ciphertext, len(plaintext)))

def decrypt(ciphertext):
    private_key = load_private_key()
    d, n = private_key
    decrypted_int = mod_exp(ciphertext, d, n)
    decrypted_message = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big').decode()
    return decrypted_message

def sign_message(message):
    private_key = load_private_key()
    d, n = private_key
    # Hash the message
    hash_bytes = hashlib.sha256(message.encode()).digest()
    hash_int = int.from_bytes(hash_bytes, 'big')
    if hash_int >= n:
        raise ValueError("Hash value is too large for the current RSA key size.")
    signature = mod_exp(hash_int, d, n)
    signature_signed_messages.append((message, signature))
    print("Message signed and stored.")

def verify_signature(signature, message):
    public_key = load_public_key()
    e, n = public_key
    # Hash the message
    hash_bytes = hashlib.sha256(message.encode()).digest()
    hash_int = int.from_bytes(hash_bytes, 'big')
    decrypted_signature = mod_exp(signature, e, n)
    if decrypted_signature == hash_int:
        print("Signature is valid.")
    else:
        print("Signature is invalid.")

def is_prime(n, k=5):
    """Miller-Rabin Primality Test."""
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0:
        return False

    # Write n-1 as 2^s * d
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1

    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = mod_exp(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = mod_exp(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_large_prime(bits=1024):
    while True:
        prime_candidate = random.getrandbits(bits)
        prime_candidate |= (1 << bits - 1) | 1  # Ensure it's odd and has the correct bit length
        if is_prime(prime_candidate):
            return prime_candidate

def generate_rsa_keys():
    global public_key, private_key
    p = generate_large_prime()
    q = generate_large_prime()
    while p == q:
        q = generate_large_prime()
    public_key, private_key = generate_keypair(p, q)
    with open('public_key.pem', 'w') as f:
        f.write(f"{public_key[0]},{public_key[1]}")
    with open('private_key.pem', 'w') as f:
        f.write(f"{private_key[0]},{private_key[1]}")

# Function to load signed messages
def load_signed_messages():
    if not signature_signed_messages:
        print("No signed messages available.")
        return
    print("The following signed messages are available:")
    for idx, (message, _) in enumerate(signature_signed_messages):
        print(f"\t{idx + 1}: {message}")
    print(">> ", end="")
    msg_choice = int(input())
    if msg_choice in range(1, len(signature_signed_messages) + 1):
        message, signature = signature_signed_messages[msg_choice - 1]
        verify_signature(signature, message)

# Function to load encrypted messages
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
        encrypted_message = decrypt(encrypted_messages[user_choice - 1][0])
        print(f"The decrypted message is: {encrypted_message}")

# Function to show current RSA keys
def show_current_keys():
    with open('public_key.pem', 'r') as f:
        public_key = f.read()
    with open('private_key.pem', 'r') as f:
        private_key = f.read()

    # Print the keys
    print(f"Public key: {public_key}")
    print(f"Private key: {private_key}")

# Menu function
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
                                    encrypt(message)
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
                                elif user_choice == 3:
                                    show_current_keys()
                                elif user_choice == 4:
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

# Run the menu
if __name__ == "__main__":
    generate_rsa_keys()
    menu()
