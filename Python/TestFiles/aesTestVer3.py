import argparse
import codecs
import os
import re
from colorama import Fore, Style
from termcolor import colored
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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

    # Pad file contents to be a multiple of the block size
    #padding = 16 - (len(file_contents) % 16)
    # Pad string to be a multiple of the block size
    padding = 16 - (len(file_contents) % 16)
    file_contents += b'\x00' * padding
    #string += b'\x00' * padding

    # Encrypt file contents
    encrypted_contents = encryptor.update(file_contents) + encryptor.finalize()

    # Encrypt the data
    #encrypted_data = encryptor.update(file_data) + encryptor.finalize()

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
'''
# 1st New Function to try out
def encrypt_strings(strings, password, key_size=256, key=None, encoding='utf-8'):
    # Generate key from password
    if key is None:
        key = os.urandom(key_size // 8)
    backend = default_backend()
    encrypted_strings = []
    for string in strings:
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
        encrypted_strings.append(ciphertext)

    return encrypted_strings
'''
'''
# 2nd New function to try out
def encrypt_strings(strings, password, key_size=256, key=None, encoding='utf-8'):
    encrypted_strings = []
    for string in strings:
        # Generate key from password
        if key is None:
            key = password
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
        encrypted_strings.append(ciphertext)
    return encrypted_strings

'''

'''
OLD FUNCTION
def encrypt_strings(strings, password, key_size=256, key=None, encoding='utf-8'):
    # Generate key from password
    salt = b'salt'
    if key is None:
        key = os.urandom(key_size // 8)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(os.urandom(16)), backend=backend)
    encryptor = cipher.encryptor()

    encrypted_strings = []
    for name, string in strings:
        

        # Encode String
        string = string.encode(encoding)

        # Add a null byte to the clear text string
        string = string + b'\x00'

        # Pad string to be a multiple of the block size
        padding = 16 - (len(string) % 16)
        string += b'\x00' * padding
        
        # Encrypt string
        ciphertext = encryptor.update(string) + encryptor.finalize()
        encrypted_strings.append((index, ciphertext))

    # Print encryption key and encrypted string in desired format
    key_hex = ', '.join(['0x{:02x}'.format(b) for b in key])
    print(colored(f'[+] String Encryption Key = {{ {key_hex} }};', 'green'))
    for name, encrypted_string in encrypted_strings:
        ciphertext_hex = ', '.join(['0x{:02x}'.format(b) for b in encrypted_string])
        print(colored(f'[+] Encrypted String {name} = {{ {ciphertext_hex} }};', 'red'))

    # Return encrypted strings
    return encrypted_strings
'''


'''
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

def decrypt_string(encryption_key, encrypted_string, encoding='utf-8'):
    # Parse the encryption key string to extract the hexadecimal values
    key = bytes.fromhex(encryption_key.replace(',', '').replace('0x', ''))

    # Parse the encrypted string to extract the hexadecimal values
    ciphertext = bytes.fromhex(encrypted_string.replace(',', '').replace('0x', ''))

    # Perform decryption
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(os.urandom(16)), backend=backend)
    decryptor = cipher.decryptor()
    string = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding from the decrypted string
    string = string.rstrip(b'\0')

    # Decode the decrypted string using the specified encoding
    decoded_string = string.decode(encoding)

    # Return the decrypted string
    return decoded_string
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

# Added Hex String Parser
def parse_hex_string(hex_string):
    hex_string = hex_string.strip().split(',')
    return bytes([int(x.strip(), 16) for x in hex_string])


def main():
    #parser = argparse.ArgumentParser(description='Encrypt and decrypt files and strings using AES encryption')
    parser = argparse.ArgumentParser(description='Encrypt files and strings using AES-CBC encryption')
    parser.add_argument('-e', '--encrypt', nargs='+', help='File(s) or string(s) to encrypt')
    #parser.add_argument('-d', '--decrypt', nargs='+', help='File(s) or string(s) to decrypt')
    #parser.add_argument('-p', '--password', help='Password to use for encryption/decryption')
    parser.add_argument('-s', '--strings', nargs='+', help='The string(s) to encrypt')
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
    
    # Encrypt the strings if the --strings option is given
    if args.strings:
        if args.password:
            password = parse_hex_string(args.password) if '0x' in args.password else args.password.encode("utf-8")
        else:
            password = get_random_bytes(args.keysize//8)
        strings = [(name, string) for name, string in zip(args.strings, args.strings)]
        encrypted_strings = encrypt_strings(strings, password, args.keysize)
        for name, encrypted_string in encrypted_strings:
            print(f'Encrypted string {name}: {encrypted_string.hex()}')

    '''
    # new Encrypt Strings function for Main to try out
    if args.strings:
    if args.random:
        password = get_random_bytes(args.keysize//8)
    else:
        password = parse_hex_string(args.password) if args.password and '0x' in args.password else args.password.encode("utf-8")
    strings = [(name, string) for name, string in zip(args.names, args.strings)]
    encrypted_strings = encrypt_strings(args.strings, password, args.keysize)
    for name, encrypted_string in enumerate(encrypted_strings):
        print(f'Encrypted string {name}: {encrypted_string.hex()}')

    '''

    '''
    if args.strings:
        if args.random:
            password = get_random_bytes(args.keysize//8)
        else:
            password = parse_hex_string(args.password) if args.password and '0x' in args.password else args.password.encode("utf-8")
        strings = [(string, string) for string in args.strings]
        encrypted_strings = encrypt_strings(strings, password, args.keysize)
        for i, encrypted_string in zip(range(len(args.strings)), encrypted_strings):
            print(f'Encrypted string {i+1}: {encrypted_string.hex()}')
        #for string, encrypted_string in encrypted_strings:
        #    print(f'Encrypted string {string}: {encrypted_string.hex()}')
    '''
    '''
    Disabled Decrypt functionality as it not working properly for the moment
    if args.decrypt:
        if args.random:
            password = get_random_bytes(args.keysize//8)
        else:
            password = args.password.encode()
            #password = parse_hex_string(args.password) if args.password and '0x' in args.password else args.password.encode()
        for item in args.decrypt:
            if os.path.isfile(item):
                decrypt_file(item, password, args.keysize)
            else:
                encryption_key_str = args.password
                encrypted_string = item
                decrypted_string = decrypt_string(encryption_key_str, encrypted_string, encoding= 'utf-8')
                print(decrypted_string)
                #decrypted_string = decrypt_string(item, password)
                #print(decrypted_string)
                #encrypted_string = parse_hex_string(item) if item and '0x' in item else item.encode()
                #decrypt_string(encrypted_string, password, args.keysize)
                #decrypt_string(encrypted_string, password)
    if args.hex:
        hex_to_bin(args.hex)
    '''

if __name__ == '__main__':
    main()
