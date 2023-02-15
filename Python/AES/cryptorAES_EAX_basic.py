from termcolor import colored
import os
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

def encrypt_file_or_string(file_or_string, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    if os.path.isfile(file_or_string):
        with open(file_or_string, 'rb') as f:
            plaintext = f.read()
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)
            return (ciphertext, nonce, tag)
    else:
        plaintext = file_or_string.encode()
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return (ciphertext, nonce, tag)

def encrypt_files_or_strings(file_or_strings):
    key = get_random_bytes(16)
    key_shellcode = bytearray(key)
    print('AES key:', key.hex())
    print('AES key shellcode:', ''.join(f'\\x{b:02x}' for b in key_shellcode))
    for file_or_string in file_or_strings:
        if os.path.isfile(file_or_string):
            (ciphertext, nonce, tag) = encrypt_file_or_string(file_or_string, key)
            with open(file_or_string + '.enc', 'wb') as f:
                [f.write(x) for x in (nonce, tag, ciphertext)]
            shellcode = bytearray(ciphertext)
            shellcode_with_null = ''.join(f'\\x{b:02x}' for b in shellcode) + '\\x00'
            print(f"{file_or_string} : Shellcode of the encrypted file: ",colored(shellcode_with_null, 'red'))
            print(f"{file_or_string} : Number of bytes for the encrypted file: ", os.path.getsize(file_or_string + '.enc'))
        else:
            (ciphertext, nonce, tag) = encrypt_file_or_string(file_or_string, key)
            shellcode = bytearray(ciphertext)
            shellcode_with_null = ''.join(f'\\x{b:02x}' for b in shellcode) + '\\x00'
            print(f"{file_or_string} : Shellcode of the encrypted string: ",colored(shellcode_with_null, 'blue'))
if __name__ == "__main__":
    input_data = input("Enter data to encrypt(file path or string): ")
    encrypt_files_or_strings(input_data.split(','))

