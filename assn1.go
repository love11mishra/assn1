package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.
//
import (

	// You neet to add with
	// go get github.com/sarkarbidya/CS628-assn1/userlib
	"crypto/rsa"

	"github.com/sarkarbidya/CS628-assn1/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...

	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// test
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

var configBlockSize = 4096 //Do not modify this variable

//setBlockSize - sets the global variable denoting blocksize to the passed parameter. This will be called only once in the beginning of the execution
func setBlockSize(blocksize int) {
	configBlockSize = blocksize
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

//helper function to return hash as []byte
func Hash(datatoHash []byte) []byte {
	hasher := userlib.NewSHA256()
	hasher.Write(datatoHash)
	hash := hasher.Sum(nil)
	return hash
}

//helper function to add user data to datastore
func addUserToDataStore(user User, emac EMAC) {
	userData, _ := json.Marshal(emac)
	userKey := Hash([]byte(user.Username + user.Password))
	key := userlib.Argon2Key([]byte(user.Password), Hash([]byte(user.Username)), 16)
	EuserData := MyCFBEncrypter(userData, key)
	userlib.DatastoreSet(string(userKey), EuserData)

}

//helper function to CFBEncrypter
func MyCFBEncrypter(plainText []byte, key []byte) (ciphertext []byte) {
	ciphertext = make([]byte, userlib.BlockSize+len(plainText))
	iv := ciphertext[:userlib.BlockSize]
	copy(iv, userlib.RandomBytes(userlib.BlockSize))
	cipher := userlib.CFBEncrypter(key, iv)
	cipher.XORKeyStream(ciphertext[userlib.BlockSize:], plainText)
	return
}

func MyCFBDecrypter(ciphertext []byte, Key []byte) (plaintext []byte, err error) {
	if len(ciphertext) <= userlib.BlockSize {
		return nil, errors.New(strings.ToTitle("Invalid Ciphertext"))
	}
	iv := ciphertext[:userlib.BlockSize]
	cipher := userlib.CFBDecrypter(Key, iv)
	cipher.XORKeyStream(ciphertext[userlib.BlockSize:], ciphertext[userlib.BlockSize:])
	plaintext = ciphertext[userlib.BlockSize:]
	return plaintext, nil
}

//helper struct to store encrypted_data and mac(encrypted_data)
type EMAC struct {
	CipherText []byte
	Mac        []byte
}

type fileBlock struct {
	data   []byte
	MACKey []byte
}

type FileMetadata struct {
	//FileId     uuid.UUID
	EncryptKey []byte
	blocks     map[int]string
	size       int
}

//functio to store blocks
func storeBlock(filename string, data []byte, offset int, key []byte) string {
	addr := string(Hash([]byte(filename + string(offset))))
	Edata := MyCFBEncrypter(data, key)
	userlib.DatastoreSet(addr, Edata)
	return addr

}

//User : User structure used to store the user information
type User struct {
	Username    string
	Password    string
	Myfiles     map[string]FileMetadata
	Sharedfiles map[string]sharingRecord
	PrivateKey  userlib.PrivateKey
	PublicKey   rsa.PublicKey
}

// StoreFile : function used to create a  file
// It should store the file in blocks only if length
// of data []byte is a multiple of the blocksize; if
// this is not the case, StoreFile should return an error.
func (userdata *User) StoreFile(filename string, data []byte) (err error) {
	if len(data)%userlib.BlockSize != 0 {
		return errors.New("Invalid Filesize")
	}

	var metaData FileMetadata
	//metaData.FileId = bytesToUUID([]byte(filename))
	metaData.size = len(data) / userlib.BlockSize
	metaData.blocks = make(map[int]string)
	metaData.EncryptKey = userlib.Argon2Key([]byte(userdata.Username), []byte(filename), 16)
	//divide file into blocks
	// for i := 0; i < metaData.size; i++ {
	// 	metaData.blocks[i] = storeBlock(filename, data[], i, metaData.EncryptKey)
	// }
	userdata.Myfiles[filename] = metaData
	return
}

//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need. The length of data []byte must be a multiple of
// the block size; if it is not, AppendFile must return an error.
// AppendFile : Function to append the file
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	return

}

// LoadFile :This loads a block from a file in the Datastore.
//
// It should give an error if the file block is corrupted in any way.
// If there is no error, it must return exactly one block (of length blocksize)
// of data.
//
// LoadFile is also expected to be efficient. Reading a random block from the
// file should not fetch more than O(1) blocks from the Datastore.
// func (userdata *User) LoadFile(filename string, offset int) (data []byte, err error) {
// 	metaData := userdata.Myfiles[filename]
// 	address := metaData.blocks[offset]
// 	Edata, ok := userlib.DatastoreGet(address)

// 	return
// }

// ShareFile : Function used to the share file with other user
func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {
	return
}

// ReceiveFile:Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
// ReceiveFile : function used to receive the file details from the sender
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {
	return errors.New("err")
}

// RevokeFile : function used revoke the shared file access
func (userdata *User) RevokeFile(filename string) (err error) {
	return
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.
// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
//InitUser : function used to create user
func InitUser(username string, password string) (userdataptr *User, err error) {
	var user User
	user.Username = username
	user.Password = password
	// Checking if username or password is/are empty
	if strings.Compare(user.Username, "") == 0 || strings.Compare(user.Password, "") == 0 {
		err = errors.New("not good")
		return nil, err
	}

	//Generating RSA key
	rsaKey, err := userlib.GenerateRSAKey()
	if err != nil {
		return nil, err
	}

	// Creating maps for file management
	user.Myfiles = make(map[string]FileMetadata)
	user.Sharedfiles = make(map[string]sharingRecord)
	user.PrivateKey = *rsaKey
	user.PublicKey = rsaKey.PublicKey

	// Generating encryption key
	key := userlib.Argon2Key([]byte(user.Password), Hash([]byte(user.Username)), 16)

	// Registering public key to the keystore
	userlib.KeystoreSet(user.Username, user.PublicKey)

	//Marshalling user data, creating ciphertext and mac for userdata
	userStr, _ := json.Marshal(user)
	var userEmac EMAC
	userEmac.CipherText = MyCFBEncrypter([]byte(userStr), key)
	userEmac.Mac = Hash(userEmac.CipherText)

	//Making an entry to datastore for user
	addUserToDataStore(user, userEmac)
	return &user, nil
}

// GetUser : This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
// GetUser : function used to get the user details
func GetUser(username string, password string) (userdataptr *User, err error) {
	userKey := Hash([]byte(username + password))

	value, ok := userlib.DatastoreGet(string(userKey))

	if value == nil || ok == false {
		return nil, errors.New("Data Corrupted")
	}
	key := userlib.Argon2Key([]byte(password), Hash([]byte(username)), 16)
	userData, err := MyCFBDecrypter(value, key)
	if err != nil {
		return nil, errors.New("Data Corrupted")
	}
	var emac EMAC
	json.Unmarshal(userData, emac)
	returnedMAC := Hash(emac.CipherText)
	ok1 := userlib.Equal(emac.Mac, returnedMAC)
	if ok1 == false {
		return nil, errors.New("Data Corrupted")
	}
	var user User
	ciphertext, _ := MyCFBDecrypter(emac.CipherText, key)
	json.Unmarshal(ciphertext, user)

	return &user, nil
}
