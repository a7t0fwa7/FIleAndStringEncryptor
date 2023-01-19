import argparse
import os
import colorama
from colorama import Fore, Style

def xor_encryption(data, key):
    """Encrypts the input data using XOR encryption with the given key."""
    encrypted_data = bytearray()
    for i, byte in enumerate(data):
        encrypted_data.append(byte ^ key[i % len(key)])
    return encrypted_data

def xor_decryption(data, key):
    """Decrypts the input data using XOR encryption with the given key."""
    decrypted_data = bytearray()
    for i, byte in enumerate(data):
        decrypted_data.append(byte ^ key[i % len(key)])
    return decrypted_data

def print_shellcode(data):
    """Prints the input data in shellcode format."""
    print(Fore.MAGENTA + "Encrypted File Shellcode:" + Style.RESET_ALL)
    print("\"", end="")
    for byte in data:
        print("\\x{:02x}".format(byte), end="")
    print("\"")

def print_key(key):
    """Prints the XOR key in shellcode format."""
    print(Fore.MAGENTA + "XOR Key (Shellcode format):" + Style.RESET_ALL)
    print("\"", end="")
    for byte in key:
        print("\\x{:02x}".format(byte), end="")
    print("\"")

def main():
    colorama.init()

    parser = argparse.ArgumentParser(description="Encrypts files and strings using XOR encryption.")
    parser.add_argument("input", nargs="+", help="The file(s) or string(s) to be encrypted.")
    parser.add_argument("-k", "--key", help="The encryption key to be used. If not provided, a random key will be generated.")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt the input using the provided key.")
    args = parser.parse_args()

    input_data = b""
    input_strings = []
    for item in args.input:
        if os.path.isfile(item):
            with open(item, "rb") as file:
                input_data += file.read()
        else:
            input_data += item.encode()
            input_strings.append(item)

    key = args.key.encode() if args.key else os.urandom(len(input_data))

    if args.decrypt:
        decrypted_data = xor_decryption(input_data, key)
        print(Fore.GREEN + "Decrypted Data:" + Style.RESET_ALL)
        print(decrypted_data.decode())
    else:
        encrypted_data = xor_encryption(input_data, key)
        print_shellcode(encrypted_data)
        print("Number of bytes: ", len(encrypted_data))
        if not args.key:
            print_key(key)
        else:
            print(Fore.YELLOW + "XOR Key (Hex representation):" + Style.RESET_ALL)
            print(key.hex())
            print(Fore.LIGHTBLUE_EX + "XOR Key (Cleartext):" + Style.RESET_ALL)
            print(key.decode())
        if input_strings:
            print(Fore.GREEN + "Original strings alongside their encrypted versions:" + Style.RESET_ALL)
            for string in input_strings:
                print(Fore.YELLOW + "Original string: " + Style.RESET_ALL + string)
                print("Encrypted string: ", end="")
                print_shellcode(xor_encryption(string.encode(), key))
                print("\n")


if __name__ == "__main__":
    main()
