import re
import os
import sys
import argparse
from colorama import Fore
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from termcolor import colored, cprint

# Function to encrypt a file or string using AES
def encrypt_data(data, key, key_size=128):
    """
    Encrypts the given data (either a file or a string) using AES encryption with the given key.
    :param data: The data to encrypt (bytes)
    :param key: The key to use for encryption (bytes)
    :param key_size: The size of the key (128 or 256)
    :return: The ciphertext (bytes)
    """
    # Create a new AES cipher with the given key size
    cipher = AES.new(key, AES.MODE_EAX)

    # Encrypt the data and return the ciphertext
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext

# Function to decrypt a file or string using AES
def decrypt_data(ciphertext, key):
    """
    Decrypts the given ciphertext (either a file or a string) using AES decryption with the given key.
    :param ciphertext: The ciphertext to decrypt (bytes)
    :param key: The key to use for decryption (bytes)
    :return: The plaintext (bytes)
    """
    # Create a new AES cipher with the given key
    cipher = AES.new(key, AES.MODE_EAX)

    # Decrypt the data and return the plaintext
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

# Function to read in and encrypt a file
def encrypt_file(file_path, key, key_size=128):
    """
    Reads in the contents of the specified file and encrypts them using AES encryption with the given key.
    :param file_path: The path to the file to encrypt
    :param key: The key to use for encryption (bytes)
    :param key_size: The size of the key (128 or 256)
    :return: The ciphertext (bytes)
    """
    # Open the file and read in its contents
    with open(file_path, 'rb') as f:
        data = f.read()

    # Encrypt the file's contents and return the ciphertext
    ciphertext = encrypt_data(data, key, key_size)
    return ciphertext

# Function to read in and decrypt a file
def decrypt_file(file_path, key):
    """
    Reads in the contents of the specified file and decrypts them using AES decryption with the given key.
    :param file_path: The path to the file to decrypt
    :param key: The key to use for decryption (bytes)
    :return: The plaintext (bytes)
    """
    # Open the file and read in its contents
    with open(file_path, 'rb') as f:
        ciphertext = f.read()

    # Decrypt the file's contents and return the plaintext
    plaintext = decrypt_data(ciphertext, key)
    return plaintext

def write_shellcode_to_file(shellcode, args, file_path):
    # Convert shellcode string to bytes
    shellcode_bytes = bytes.fromhex(shellcode)

    # Write the bytes to the specified file
    with open(args.output, 'wb') as f:
        f.write(shellcode_bytes)



# Main function to handle command-line arguments and perform encryption/decryption
def main():
    # Set up the command-line argument parser
    parser = argparse.ArgumentParser(description='Encrypt/decrypt files and strings using AES. Outputs the encrypted data in shellcode format if -s/--shellcode is passed.')
    parser.add_argument('-e', '--encrypt', nargs='+', help='File(s) or string(s) to encrypt')
    parser.add_argument('-d', '--decrypt', nargs='+', help='File(s) or string(s) to decrypt')
    parser.add_argument('-k', '--key', help='AES key to use for encryption/decryption')
    parser.add_argument('-r', '--random-key', help='Generate a random AES key of the specified size (128 or 256)', type=int)
    parser.add_argument('-s', '--shellcode', action='store_true', help='Print the encrypted data in shellcode format')
    parser.add_argument('-o','--output', help='Output file name to write the shellcode')


    # Parse the command-line arguments
    args = parser.parse_args()

    # If the user wants to encrypt data
    if args.encrypt:
        # Get the key to use for encryption
        if args.key:
            key = args.key.encode()
        elif args.random_key:
            key_size = args.random_key
            key = get_random_bytes(key_size // 8)
        else:
            print(Fore.RED + 'Error: No key specified for encryption.')
            sys.exit(1)

        print(Fore.CYAN + 'AES key in shellcode format:')
        print(Fore.YELLOW + ''.join(f'\\x{byte:02x}' for byte in key) + '\\x00')
        # Encrypt the specified files and strings
        for data in args.encrypt:
            # If the data is a file, encrypt its contents
            if os.path.isfile(data):
                ciphertext = encrypt_file(data, key, key_size)
                print(Fore.GREEN + f'Successfully encrypted {data}.')
                if args.shellcode:
                    print(Fore.CYAN + 'Shellcode:')
                    print(Fore.YELLOW + ''.join(f'\\x{byte:02x}' for byte in ciphertext) + '\\x00')
                    print(Fore.LIGHTBLUE_EX + f'Encrypted shellcode size: {len(ciphertext)} bytes.')
            # If the data is a string, encrypt it
            else:
                ciphertext = encrypt_data(data.encode(), key, key_size)
                print(Fore.GREEN + f'Successfully encrypted string: {data}.')
                if args.shellcode:
                    print(Fore.CYAN + 'Shellcode:')
                    print(Fore.YELLOW + ''.join(f'\\x{byte:02x}' for byte in ciphertext) + '\\x00')
                    print(Fore.LIGHTBLUE_EX + f'Encrypted shellcode size: {len(ciphertext)} bytes.')

    # If the user wants to decrypt data
    elif args.decrypt:
        # Get the key to use for decryption
        if args.key:
            key = args.key.encode()
        else:
            print(Fore.RED + 'Error: No key specified for decryption.')
            sys.exit(1)

        # Decrypt the specified files and strings
        for data in args.decrypt:
            # If the data is a file, decrypt its contents
            if os.path.isfile(data):
                plaintext = decrypt_file(data, key)
                print(Fore.GREEN + f'Successfully decrypted {data}.')
                print(Fore.YELLOW + 'Decrypted content:')
                print(Fore.LIGHTMAGENTA_EX + plaintext.decode())
            # If the data is a string, decrypt it
            else:
                plaintext = decrypt_data(data.encode(), key)
                print(Fore.GREEN + f'Successfully decrypted string: {data}.')
                print(Fore.YELLOW + 'Decrypted content:')
                print(Fore.LIGHTMAGENTA_EX + plaintext.decode())

    if args.shellcode:
        shellcode = encrypt_data(data, key, key_size).hex()
        write_shellcode_to_file(shellcode, args)
        print(Fore.GREEN + f'Encrypted shellcode written to {args.output}')

    else:
        # If no action specified, print an error message
        print(Fore.RED + 'Error: No action specified. Use -e to encrypt or -d to decrypt.')
        sys.exit(1)

# Run the script
if __name__ == '__main__':
    main()
