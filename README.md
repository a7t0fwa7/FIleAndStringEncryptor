# FileAndStringEncryptor
- Encrypt files and strings in AES or XOR

- Usage and dependencies in respective folders

# Key Requirements for the AES script
- use pycryptodomex library, and the colorama library aswell as any other necessary libraries to create a script that performs the following tasks:
- use a key derivation function (KDF) such as scrypt or PBKDF2 (Password-Based Key Derivation Function 2) to create a key from a plaintext password for better security.
- use the codecs library if necessary
- the script will use any other libraries that are necessary for it to achieve the functionality required
- the script will allow the user to enter one or several files or one or several cleartext strings as input 
- the script will also allow to convert a hexarray of binary shellcode strings into raw bytes and output it to a binary file in ".bin" format
- When the user enters the cleartext strings the script will append a nullbyte before encrypting the string
- the script will then encrypt the files and the strings using AES encryption.
- the script will output an encrypted binary file also
- the script will allow the user to enter a plaintext password as an encryption key and encrypt it in AES 128 or 256 and will show a detailed usage on how to do this
- the script will also allow the user to choose a randomised 128 or 256 encryption password and will show a detailed usage on how to do this
- the script will print out the encrypted AES file as shellcode in the terminal in order to allow it to be incorporated into a c or c++ script at a later stage
- the script will print out the number of bytes for the encrypted file
- the script will Print the AES password in shellcode format in order to be able to use it inside a c or c++ script at a later stage
- the script will print out the unencrypted names of the strings alongside the shellcode encrypted version of the strings
- the script will print each string separately by iterating through the list
- the script will use colored output when printing to the console for ease of reading 
- the script will add a function to decrypt the files and strings, which allows the user to decrypt the file or the strings.
- the script will also be able to take as input the encrypted shellcode password or randomised shellcode password as input, and the encrypted shellcode string or file that need to be decrypted as input also
- the script will handle exceptions in case of any errors such as file not found
- the script will add detailed instructions for each command-line argument
- the script will Provide several usage examples on how to use each options


