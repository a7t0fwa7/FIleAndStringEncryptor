import argparse
import codecs
import os
import re
from termcolor import colored
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# This script works quite well except I want to modify it to use only one key for the strings and files as this currently encrypts each string and files with a seperate encryption key

def parse_hex_string(s):
    return bytes.fromhex(s[2:])

def get_random_bytes(length):
    return os.urandom(length)

def encrypt_file(file_name, password, key_size=256):
    # Generate key from password
    salt = b'salt'
    key = os.urandom(key_size // 8)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(os.urandom(16)), backend=backend)
    encryptor = cipher.encryptor()
    
    # Read the file
    with open(file_name, 'rb') as file:
        file_contents = file.read()
    # Pad string to be a multiple of the block size
    padding = 16 - (len(file_contents) % 16)
    file_contents += b'\x00' * padding
    #string += b'\x00' * padding

    # Encrypt file contents
    encrypted_contents = encryptor.update(file_contents) + encryptor.finalize()

    # Print encryption key in desired format
    key_hex = ', '.join(['0x{:02x}'.format(b) for b in key])
    print(colored(f'[+] File Encryption Key = {{ {key_hex} }};', 'blue'))

    # Print encrypted file in desired format
    encrypted_file_hex = ', '.join(['0x{:02x}'.format(b) for b in encrypted_contents])
    print(colored(f'[+] Encrypted File Output in Hex Format: {{ {encrypted_file_hex} }};', 'magenta'))

    # Write encrypted contents to file
    with open(file_name + '.enc', 'wb') as file:
        file.write(encrypted_contents)

    # Return encryption key
    return key



def encrypt_string(string, password, key_size=256, key=None, encoding='utf-8'):
    # Generate key from password
    salt = b'salt'
    if key is None:
        key = os.urandom(key_size // 8)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(os.urandom(16)), backend=backend)
    encryptor = cipher.encryptor()

    # Add a null byte to the clear text string
    string = string.encode(encoding)
    string = string + b'\x00'

    # Pad string to be a multiple of the block size
    padding = 16 - (len(string) % 16)
    string += b'\x00' * padding

    # Encrypt string
    ciphertext = encryptor.update(string) + encryptor.finalize()

    # Print encryption key and encrypted string in desired format
    key_hex = ', '.join(['0x{:02x}'.format(b) for b in key])
    print(colored(f'[+] String to Encrypt: {string.decode(encoding)}', 'cyan'))
    print(colored(f'[+] String Encryption Key = {{ {key_hex} }};', 'green'))
    ciphertext_hex = ', '.join(['0x{:02x}'.format(b) for b in ciphertext])
    print(colored(f'[+] Encrypted String = {{ {ciphertext_hex} }};', 'red'))

    return ciphertext

def hex_to_bin(hex_str):
    if not re.match("^[0-9a-fA-F]+$", hex_str):
        print("The input is not a valid hexadecimal string")
        return
    bin_str = codecs.decode(hex_str, 'hex')
    # Write binary data to file
    bin_file_path = 'shellcode.bin'
    with open(bin_file_path, 'wb') as f:
        f.write(bin_str)
    print(colored(f'[+] Hex string has been converted to binary and saved as {bin_file_path}', 'light_cyan'))
    return bin_file_path

# Added Hex String Parser
def parse_hex_string(hex_string):
    hex_string = hex_string.strip().split(',')
    return bytes([int(x.strip(), 16) for x in hex_string])


def main():
    #parser = argparse.ArgumentParser(description='Encrypt and decrypt files and strings using AES encryption')
    parser = argparse.ArgumentParser(description='Encrypt files and strings using AES-CBC encryption')
    parser.add_argument('-e', '--encrypt', nargs='+', help='File(s) or string(s) to encrypt')
    parser.add_argument('-p', '--password', help='Password to use for encryption')
    parser.add_argument('-r', '--random', action='store_true', help='Use random password for encryption')
    parser.add_argument('-k', '--keysize', type=int, choices=[128, 256], default=256, help='Key size to use for encryption (default: 256)')
    parser.add_argument('-x', '--hex', help='Convert hex string to binary file')
    
    # Parse the arguments
    args = parser.parse_args()

    # Check if the --encrypt or --decrypt option is given
    if args.encrypt:
        if args.random:
            password = get_random_bytes(args.keysize//8)
        else:
            password = parse_hex_string(args.password) if args.password and '0x' in args.password else args.password.encode('utf-8')
        for item in args.encrypt:
            if os.path.isfile(item):
                encrypt_file(item, password, args.keysize)
            else:
                encrypt_string(item, password, args.keysize)
    if args.hex:
        hex_to_bin(args.hex)

if __name__ == '__main__':
    main()
