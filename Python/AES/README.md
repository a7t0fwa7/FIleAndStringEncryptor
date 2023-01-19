# Description
I used the pycryptodomex library and termcolor to create a basic AES file and string encryptor that pushed the coloured output to the console

I then used the same crypto library, and this time the colorama library to create a more complete script that does the following:

- the script will allow the user to enter one or several files or one or several strings as input
- the script will allow the user to encrypt the files and the strings using AES encryption.
- the script will allow the user to choose a custom 128 or 256 bit encryption key
- the script will allow the user to choose a randomised 128 or 256 encryption key
- the script will print out the encrypted AES file as shellcode
- the script will print out the number of bytes for the encrypted file
- the script will Print the AES key in shellcode format in order to decrypt the file and strings
- the script will then print out the unencrypted names of the strings alongside the shellcode encrypted version of the strings
- the script will print each string separately by iterating through the list
- the script will use colored output when printing to the console, 
- the script will add a null byte at the end of the shellcode output,
- the script will add a function to decrypt the files and strings, which takes the encrypted file/string, and the AES key as input
- the script will handle exceptions in case of any errors such as file not found
- the script will add detailed explanations for each command-line argument
- the script will Provide several usage examples for the user

## Example Usage:

Print out a randomised 256 bit encrypted shell code for a msgbox.bin file and different strings

`python .\cryptorAEScomplete.py -e msgbox.bin, VirtualAlloc, GetProcAddress, GetRemoteThread -r 256 -s`

Dependencies
Pycryptodomex `pip install pycryptodomex`
Termcolor     `pip install termcolor`
Colorama      `pip install colorama`