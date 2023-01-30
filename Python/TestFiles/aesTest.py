import argparse
import codecs
import os
import re
import binascii
from colorama import Fore, Style
from termcolor import colored
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

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

    # Pad file contents to be a multiple of the block size
    padding = 16 - (len(file_contents) % 16)
    file_contents += b'\0' * padding

    # Encrypt file contents
    encrypted_contents = encryptor.update(file_contents) + encryptor.finalize()

    # Encrypt the data
    #encrypted_data = encryptor.update(file_data) + encryptor.finalize()

    # Print encryption key in desired format
    key_hex = ','.join(['0x{:02x}'.format(b) for b in key])
    print(colored(f'[+] File Encryption Key = {{{key_hex}}};', 'light_blue'))

    # Print encrypted file in desired format
    encrypted_file_hex = ','.join(['0x{:02x}'.format(b) for b in encrypted_contents])
    print(colored(f'[+] Encrypted File Output in Hex Format: {{{encrypted_file_hex}}};', 'light_magenta'))

    # Write encrypted contents to file
    with open(file_name + '.enc', 'wb') as file:
        file.write(encrypted_contents)

    # Return encryption key
    return key



def encrypt_string(string, password, key_size=256):
    # Generate key from password
    salt = b'salt'
    key = os.urandom(key_size // 8)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(os.urandom(16)), backend=backend)
    encryptor = cipher.encryptor()

    # Add a null byte to the clear text string
    string = string + '\x00'

    # Pad string to be a multiple of the block size
    padding = 16 - (len(string) % 16)
    #string += '\0' + '\0' * (padding - 1)
    string += '\0' * padding

    # Encrypt string
    ciphertext = encryptor.update(string.encode()) + encryptor.finalize()

    # Print encryption key and encrypted string in desired format
    key_hex = ','.join(['0x{:02x}'.format(b) for b in key])
    print(colored(f'[+] String to Encrypt: {string}', 'cyan'))
    print(colored(f'[+] String Encryption Key = {{{key_hex}}};', 'green'))
    ciphertext_hex = ','.join(['0x{:02x}'.format(b) for b in ciphertext])
    print(colored(f'[+] Encrypted String = {{{ciphertext_hex}}};', 'red'))

    return ciphertext


def decrypt_file(file_path, password, key_size=256):
    # Derive key from password
    key = scrypt(password, salt=b'salt', key_len=key_size//8, N=16384, r=8,p=1)
    # Read encrypted file data
    with open(file_path, 'rb') as f:
        data = f.read()
    # Extract initialization vector
    iv = data[:AES.block_size]
    ciphertext = data[AES.block_size:]
    # Create AES cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Decrypt data
    data = cipher.decrypt(ciphertext)
    # Remove padding
    padding = data[-1]
    data = data[:-padding]
        # Write decrypted data to new file
    decrypted_file_path = file_path + '.decrypted'
    with open(decrypted_file_path, 'wb') as f:
        f.write(data)
    print(f'{Fore.GREEN}[+] {file_path} has been decrypted and saved as {decrypted_file_path}{Style.RESET_ALL}')
    return decrypted_file_path

def decrypt_string(ciphertext, key, key_size=256):
    # Convert encryption key from hex string to bytes
    key = bytes.fromhex(key.replace("0x", ""))

    # Initialize cipher and decryptor
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(os.urandom(16)), backend=backend)
    decryptor = cipher.decryptor()

    # Decrypt string
    cleartext = decryptor.update(ciphertext) + decryptor.finalize()

    # Strip padding from decrypted string
    cleartext = cleartext.rstrip(b'\0')

    return cleartext.decode()


'''
OLD DECRYPT STRING FUNCTION
def decrypt_string(ciphertext, password, key_size=256):
    # Derive key from password
    key = scrypt(password, salt=b'salt', key_len=key_size//8)
    # Extract initialization vector
    iv = ciphertext[:AES.block_size]
    ciphertext = ciphertext[AES.block_size:]
    # Create AES cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Decrypt string
    string = cipher.decrypt(ciphertext).decode()
    # Remove null byte and padding
    string = string.rstrip('\0')
    print(f'{Fore.GREEN}[+] String has been decrypted:{string}{Style.RESET_ALL}')
    return string
'''
def hex_to_bin(hex_str):
    if not re.match("^[0-9a-fA-F]+$", hex_str):
        print("The input is not a valid hexadecimal string")
        return
    bin_str = codecs.decode(hex_str, 'hex')
    # Write binary data to file
    bin_file_path = 'shellcode.bin'
    with open(bin_file_path, 'wb') as f:
        f.write(bin_str)
    print(f'{Fore.GREEN}[+] Hex string has been converted to binary and saved as {bin_file_path}{Style.RESET_ALL}')
    return bin_file_path


def main():
    parser = argparse.ArgumentParser(description='Encrypt and decrypt files and strings using AES encryption')
    parser.add_argument('-e', '--encrypt', nargs='+', help='File(s) or string(s) to encrypt')
    parser.add_argument('-d', '--decrypt', nargs='+', help='File(s) or string(s) to decrypt')
    parser.add_argument('-p', '--password', help='Password to use for encryption/decryption')
    parser.add_argument('-r', '--random', action='store_true', help='Use random password for encryption')
    parser.add_argument('-k', '--keysize', type=int, choices=[128, 256], default=256, help='Key size to use for encryption (default: 256)')
    parser.add_argument('-x', '--hex', help='Convert hex string to binary file')
    args = parser.parse_args()

    if args.encrypt:
        if args.random:
            password = get_random_bytes(args.keysize//8)
        else:
            password = args.password.encode()
        for item in args.encrypt:
            if os.path.isfile(item):
                encrypt_file(item, password, args.keysize)
            else:
                encrypt_string(item, password, args.keysize)
    if args.decrypt:
        if args.random:
            password = get_random_bytes(args.keysize//8)
        else:
            password = args.password.encode()
        for item in args.decrypt:
            if os.path.isfile(item):
                decrypt_file(item, password, args.keysize)
            else:
                decrypt_string(item, password, args.keysize)
    if args.hex:
        hex_to_bin(args.hex)

if __name__ == '__main__':
    main()
