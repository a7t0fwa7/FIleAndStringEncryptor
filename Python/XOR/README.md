# What it does
**XOR encryptor**

- The script will take input in the form of one or more files or strings.
- The script will provide options for the user to encrypt the input using XOR encryption and choose either a custom encryption key or a randomized key.
- The script will print the encrypted input in the form of shellcode, as well as the number of bytes in the encrypted file.
- The script will also print the XOR key in shellcode format, in order to allow for decryption.
- The script will print the original strings alongside their encrypted versions, iterating through a list of strings if multiple are provided.
- The script will use colored output for ease of reading.
- The script will include a null byte at the end of the shellcode output, and a function for decrypting the input using the XOR key.
- The script will handle exceptions for errors such as "file not found."
- The script will include detailed explanations for each command-line argument and provide usage examples for the user.

## Usage

**Encrypt file msgbox.bin with our own key and encrypt a string or several strings**
`python .\cryptorXOR.py -k 1234567890abcdef msgbox.bin, VirtualAlloc, CreateRemoteThread`

**Encrypt a msgbox.bin file and a string without providing your own key. This will generate a random XOR key that will be printed to the console**
`python .\cryptorXOR.py  msgbox.bin, VirtualAlloc`

## Dependencies
`pip install colorama`