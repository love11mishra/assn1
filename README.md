

## README

This is a design document for a secure file storage system. The system is designed to provide secure storage and sharing of files between users. The system uses a combination of encryption, authentication, and key management techniques to ensure the confidentiality and integrity of user data.

### User Struct

The user struct is the central data structure used by the system. It contains the following fields:

- **username**: The username of the user.
- **password**: The password of the user.
- **RSA private key pair**: The RSA private key pair of the user, used for encryption and decryption of data.
- **Myfiles**: A map that maps a file to a Filemetadata struct.
- **HMAC**: A message authentication code used to ensure the integrity of the User struct.
- **List of keys used to encrypt each block of file**: A list of keys used to encrypt each block of a file.
- **List of addresses of all the file blocks and number of blocks**: A list of addresses of all the file blocks and the number of blocks.

### InitUser(username string, password string)

The InitUser function is used to initialize a user account. It generates an RSA key pair and populates the User struct with the user's data. It also generates a key 'K' using Argon2Key on the password and username as salt. The User struct is then encrypted using CFBEncrypter and HMAC, and saved in the datastore at location userID. The RSA public key is also registered with the key store using the username.

### GetUser(username string, password string)

The GetUser function is used to retrieve a user's account information. It generates key 'K' using the username and password, regenerates the userID, and loads the User struct from the datastore. It then checks the HMAC and decrypts the User struct.

### StoreFile(filename string, data []byte)

The StoreFile function is used to store a file in a user's account. It generates a Filemetadata struct and stores it in the user's Myfiles map. It also calculates the size of the file, divides it into blocks, and calculates the address for each block. The encryption key is generated using Argon2Key and stored in the Filemetadata struct. The file is then encrypted using CFBEncrypter with the encryption key, and HMAC is calculated and stored in the Filemetadata struct.

### LoadFile(filename string, blockOffset integer)

The LoadFile function is used to load a file from a user's account for a particular block offset. It loads the file by calculating the address and encryption key in the same manner as done in StoreFile. It then fetches, decrypts, verifies, and accesses the data.

### AppendFile(filename string, data []byte)

The AppendFile function is used to append data to an existing file in a user's account. It loads the file metadata using the filename, verifies that the file is not corrupted, and checks if the size of the data is a multiple of the block size. It then stores the data and updates the entries in the Filemetadata.

### ShareFile()

The ShareFile function is used to share a file between users. It retrieves the Filemetadata of the file from the sender's Myfiles map and retrieves the receiver's public RSA key from the keystore. It then uses this key to encrypt the metadata and returns the encrypted message and signature.

### Receive Share()

The Receive Share function is used to receive a shared file. It retrieves the sender's public key from the keystore, verifies the RSA signature, and uses the receiver's private key to decrypt the data. The data is then saved in the receiver's Myfile map under the given filename.

### RevokeFile()

The RevokeFile function is used to revoke access to a shared file
