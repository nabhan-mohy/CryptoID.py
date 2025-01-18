CryptoID – A Powerful Advanced Hash Identifier Tool
CryptoID is a versatile and easy-to-use Python tool designed to identify, encode, and decode various cryptographic hashes. Whether you're a cybersecurity professional, a pen tester, or a developer, CryptoID helps you easily identify hashes from a wide range of algorithms and even suggests the appropriate cracking tools.

Features:
Identify Hashes: Identify and match input hashes to their respective algorithms.
Encode Strings to Hashes: Hash strings using popular algorithms like MD5, SHA-1, SHA-256, bcrypt, NTLM, and more.
Decode Hashes: Decode base64 or hex-encoded hashes.
Advanced Hash Analysis: Calculate entropy to measure the randomness of a hash.
Tool Suggestions: Suggests tools for cracking specific hashes based on their algorithm type.
Supported Hash Algorithms:
MD5, SHA-1, SHA-256, SHA-512, SHA-3
bcrypt, PBKDF2, NTLM, LanMan
RIPEMD, Whirlpool, Blake2, GOST
Ethereum Keccak, CRC, MurmurHash, xxHash, SipHash
Installation:
Clone the repository:

bash
Copy
Edit
git clone https://github.com/nabhan-mohy/CryptoID.py
Install dependencies:

bash
Copy
Edit
pip install -r requirements.txt
Run the tool:

bash
Copy
Edit
python CryptoID.py
Example Usage:
Identify a hash:
bash
Copy
Edit
python CryptoID.py
Enter the hash to identify: 5d41402abc4b2a76b9719d911017c592
Requirements:
Python 3.x
bcrypt, hashlib, pyfiglet, and other dependencies listed in requirements.txt
License:
Distributed under the MIT License. See LICENSE for more information.
![Screenshot_2025-01-18_02_17_28](https://github.com/user-attachments/assets/a91a5658-560c-44c2-a746-3aefef076450)


