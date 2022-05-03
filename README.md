# locker
Rust Encryption

Rust Encryption and Decryption Program For Personal Use

Usage: locker [encrypt || decrypt] [path] [key path] [nonce path]

Note: The CLI Args Are NOT Case Sensitive

Encrypt:
Encrypts Files of Directory Including All Files Located in Subdirectories
Creates and Stores Encryption Key In User Designated Key Path
Creates and Stores Nonce In User Designated Nonce Path

Decrypt:
Decrypts Files of Directory Including All Files Located in Subdirectories
Loads Encryption Key From User Designated Key Path
Loads Nonce From User Designated Nonce Path
