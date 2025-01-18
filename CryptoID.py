import re
import argparse
import json
import base64
import hashlib
import bcrypt
from math import log2
from passlib.hash import pbkdf2_sha256, nthash
import pyfiglet

# Database of hash algorithms
HASH_DATABASE = [
    {"name": "MD5", "length": 32, "regex": r"^[a-fA-F0-9]{32}$", "description": "Message Digest 5 (MD5)."},
    {"name": "SHA-1", "length": 40, "regex": r"^[a-fA-F0-9]{40}$", "description": "Secure Hash Algorithm 1 (SHA-1)."},
    {"name": "SHA-256", "length": 64, "regex": r"^[a-fA-F0-9]{64}$", "description": "Secure Hash Algorithm 256 (SHA-256)."},
    {"name": "SHA-512", "length": 128, "regex": r"^[a-fA-F0-9]{128}$", "description": "Secure Hash Algorithm 512 (SHA-512)."},
    {"name": "bcrypt", "regex": r"^\$2[aby]?\$[0-9]{2}\$.{53}$", "description": "bcrypt password hash."},
    {"name": "NTLM", "length": 32, "regex": r"^[a-fA-F0-9]{32}$", "description": "NTLM hash (Windows)."},
    {"name": "LanMan", "regex": r"^[a-fA-F0-9]{32}$", "description": "LanMan hash (Windows legacy)."},
    {"name": "MySQL", "regex": r"^\*[A-F0-9]{40}$", "description": "MySQL password hash."},
    {"name": "Oracle", "regex": r"^\{SHA\}[a-zA-Z0-9+/=]{28}$", "description": "Oracle password hash."},
    {"name": "Cisco Type 7", "regex": r"^[0-9]{2}[A-F0-9]+$", "description": "Cisco Type 7 password hash."},
    {"name": "SHA-224", "length": 56, "regex": r"^[a-fA-F0-9]{56}$", "description": "Secure Hash Algorithm 224 (SHA-224)."},
    {"name": "RIPEMD", "regex": r"^[a-fA-F0-9]{32,64}$", "description": "RIPEMD Family of Hash Functions."},
    {"name": "Whirlpool", "regex": r"^[a-fA-F0-9]{128}$", "description": "Whirlpool Hash."},
    {"name": "Tiger", "regex": r"^[a-fA-F0-9]{48}$", "description": "Tiger Hash Function."},
    {"name": "Blake2", "regex": r"^[a-fA-F0-9]{64,128}$", "description": "Blake2 Hash Family."},
    {"name": "GOST", "regex": r"^[a-fA-F0-9]{64}$", "description": "GOST Hash Function."},
    {"name": "Ethereum", "regex": r"^0x[a-fA-F0-9]{64}$", "description": "Ethereum Keccak Hash."},
    {"name": "CRC", "regex": r"^[a-fA-F0-9]{8}$", "description": "Cyclic Redundancy Check (CRC)."},
    {"name": "MurmurHash", "regex": r"^[a-fA-F0-9]{8}$", "description": "MurmurHash Function."},
    {"name": "xxHash", "regex": r"^[a-fA-F0-9]{8,16}$", "description": "xxHash Function."},
    {"name": "SipHash", "regex": r"^[a-fA-F0-9]{16}$", "description": "SipHash Function."}
]

# Advanced hash analysis
def calculate_entropy(input_string):
    """Calculate the Shannon entropy of a string."""
    if not input_string:
        return 0
    probabilities = [input_string.count(c) / len(input_string) for c in set(input_string)]
    return -sum(p * log2(p) for p in probabilities)

# Hash cracking suggestions
def suggest_cracking_tool(hash_name):
    """Suggest tools for cracking specific hash types."""
    tool_suggestions = {
        "MD5": "Use Hashcat with mode 0 or John the Ripper.",
        "SHA-1": "Use Hashcat with mode 100 or John the Ripper.",
        "SHA-256": "Use Hashcat with mode 1400 or John the Ripper.",
        "bcrypt": "Use Hashcat with mode 3200 or John the Ripper.",
        "NTLM": "Use Hashcat with mode 1000 or John the Ripper.",
        "MySQL": "Use Hashcat with mode 300 or John the Ripper.",
        "Oracle": "Use specialized Oracle password cracking tools.",
        "Cisco Type 7": "Use tools like cdecrypt or hashcat mode 5700.",
        "RIPEMD": "Use Hashcat or specialized tools.",
        "Whirlpool": "Use Hashcat or similar tools.",
        "Blake2": "Use Blake2-compatible tools.",
        "GOST": "Use GOST-specific cracking tools.",
        "Ethereum": "Analyze with Ethereum transaction tools.",
        "CRC": "Utilize CRC checksum analysis tools."
    }
    return tool_suggestions.get(hash_name, "No specific tool recommendation available.")

# Encoding and decoding for various hash algorithms
def encode_hash(input_string, algorithm):
    """Encode a string using the specified hash algorithm."""
    try:
        if algorithm == "MD5":
            return hashlib.md5(input_string.encode()).hexdigest()
        elif algorithm == "SHA-1":
            return hashlib.sha1(input_string.encode()).hexdigest()
        elif algorithm == "SHA-256":
            return hashlib.sha256(input_string.encode()).hexdigest()
        elif algorithm == "SHA-3":
            return hashlib.sha3_256(input_string.encode()).hexdigest()
        elif algorithm == "RIPEMD":
            # Example: RIPEMD-160 (use a library if needed)
            return hashlib.new('ripemd160', input_string.encode()).hexdigest()
        elif algorithm == "Whirlpool":
            return hashlib.new('whirlpool', input_string.encode()).hexdigest()
        elif algorithm == "Blake2":
            return hashlib.blake2b(input_string.encode()).hexdigest()
        elif algorithm == "GOST":
            return hashlib.new('gost', input_string.encode()).hexdigest()
        elif algorithm == "bcrypt":
            return bcrypt.hashpw(input_string.encode(), bcrypt.gensalt()).decode()
        elif algorithm == "PBKDF2":
            return pbkdf2_sha256.hash(input_string)
        elif algorithm == "NTLM":
            return nthash.hash(input_string)
        elif algorithm == "LanMan":
            return nthash.hash(input_string).upper()[:16]  # Simulates LanMan truncation
    except Exception as e:
        return f"Error: {str(e)}"
    return None

# Decode hash (base64 and hex support only)
def decode_hash(hash_input, encoding_type):
    try:
        if encoding_type == "base64":
            return base64.b64decode(hash_input).decode()
        elif encoding_type == "hex":
            return bytes.fromhex(hash_input).decode()
    except Exception as e:
        return f"Error: {str(e)}"
    return None

# Identify hash
def identify_hash(hash_input):
    matches = []
    for algo in HASH_DATABASE:
        if re.match(algo["regex"], hash_input):
            matches.append(algo)
    return matches

# Main function
def main():
    # Print the name 'CryptoID' in a large font
    ascii_art = pyfiglet.figlet_format("CryptoID", font="slant")  # You can choose other fonts as well
    print("\033[1;32m" + ascii_art)

    print("=========================================")
    print(" A Powerful Advanced Hash Identifier Tool ")
    print("=========================================")

    print("Select a hash operation:")
    print("[1] Identify a hash")
    print("[2] Encode a string to hash")
    print("[3] Decode a hash")
    print("[4] Exit")

    choice = input("Enter your choice (1-4): ").strip()

    if choice == "1":
        hash_input = input("Enter the hash to identify: ").strip()
        matches = identify_hash(hash_input)
        entropy = calculate_entropy(hash_input)
        print(f"Input Hash: {hash_input}")
        print(f"Entropy: {entropy:.4f}")
        if matches:
            for match in matches:
                print(f"- Algorithm: {match['name']}")
                print(f"  Description: {match['description']}")
        else:
            print("No matching hash type found.")

    elif choice == "2":
        string_input = input("Enter the string to encode: ").strip()
        algorithm = input("Enter the algorithm (e.g., MD5, SHA-1, SHA-256): ").strip()
        encoded = encode_hash(string_input, algorithm)
        print(f"Encoded ({algorithm}): {encoded}")

    elif choice == "3":
        hash_input = input("Enter the hash to decode: ").strip()
        encoding_type = input("Enter the encoding type (base64/hex): ").strip()
        decoded = decode_hash(hash_input, encoding_type)
        print(f"Decoded ({encoding_type}): {decoded}")

    elif choice == "4":
        print("Exiting...")
        exit(0)
    else:
        print("\033[1;31mInvalid choice. Please enter a number between 1 and 4.")

if __name__ == "__main__":
    main()
