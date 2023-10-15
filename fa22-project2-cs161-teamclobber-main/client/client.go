package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type HMACWrapper struct {
	Ciphertext []byte
	// Ciphertext: This is Marshaled Encrypted Plain structure.
	// To retrive the original plain structure, Unmarshal HMACWrapper, Decrypt Ciphertext, Unmarshal it.

	MAC []byte
	// HMACEval(MACKey, Ciphertext)
	// Value to check with HMACEqual(MAC, HMACEval(MACKey, Ciphertext)) == true
	// This will protect Ciphertext not to change unless they have MACKey
}
type User struct {
	Username               string
	UserSignKey            userlib.DSSignKey // Signature key. There's the pair key inside KeyStore in public at KeystoreGet(username + "-" + "UserSignVerificationKey")
	UserPublicDECKey       userlib.PKEDecKey // Symmetric Decryption key. There's a pair key inside KeyStore in public at Keystore(username + "-" + "UserPublicENCKey")
	SecretSaltForFileNames []byte            // hidden salt used to derive unique uuid from the filename
	MACKey                 []byte            // Key for HMACWrapper, needs password to derive so we keep here
	SessionKey             []byte            // Session key, derived by password

	NameSpaceUUID   uuid.UUID // Namespace that stores all of filenames this user has
	NameSpaceMACKey []byte
	NameSpaceDECKEY []byte
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}
type FileInfo struct {
	IndicatorStructUUID        uuid.UUID
	IndicatorStructMACKey      []byte
	IndicatorStructDECKey      []byte
	HasChild                   bool
	ChildIndicatorStructUUID   uuid.UUID
	ChildIndicatorStructMACKey []byte
	ChildIndicatorStructDECKey []byte
}
type FileInfoDict struct {
	// (username, FileInfo)
	Dict map[string]FileInfo
}
type NameSpaceStruct struct {
	// has all the (filename, FileInfoDict)
	NameSpace map[string]FileInfoDict
}
type LinkedListBlock struct {
	ContentUUID uuid.UUID // Remember HMACWrapper
	NextUUID    uuid.UUID
	LastPtr     bool // Is this the last block of Linked list?
	// If true then don't look for NextUUID
	// If false then there is a valid NextUUID
}
type FileStruct struct {
	HeadPtr uuid.UUID
	TailPtr uuid.UUID
}
type IndicatorStruct struct {
	FileOrNextIndicatorStructMACKey []byte    //MACKey of the FileStruct, LinkedListBlock, content, and HMACWrapper of them
	FileOrNextIndicatorStructDECKey []byte    //DECKey of the FileStruct, LinkedListBlock, content, and HMACWrapper of them
	FileOrNextIndicatorStructUUID   uuid.UUID //UUID of the FileStruct if LastPtr == True, otherwise UUID of next Indicator Struct
	LastPtr                         bool      // Is this indicator the last pointer before the filestructure?
}

func IndicatorStructMaker(FileMACKey []byte, FileDECKey []byte, FileStructUUID uuid.UUID, LastPtr bool) (UserIndicatorStruct IndicatorStruct) {
	UserIndicatorStruct.FileOrNextIndicatorStructMACKey = FileMACKey
	UserIndicatorStruct.FileOrNextIndicatorStructDECKey = FileDECKey
	UserIndicatorStruct.FileOrNextIndicatorStructUUID = FileStructUUID
	UserIndicatorStruct.LastPtr = LastPtr
	return UserIndicatorStruct
}

type InvitationStruct struct {
	ParentIndicatorStructUUID   uuid.UUID
	ParentIndicatorStructMACKey []byte
	ParentIndicatorStructDECKey []byte
	Childname                   string
	ChildUUID                   uuid.UUID // Child IndicatorStruct must placed here
	ChildMACKey                 []byte    // Child must HMAC with this
	ChildDECKey                 []byte    // Child must ENC/DEC their Child IndicatorStruct with this
}

// I'm going to name it something more intuitive :) !if we change it to benson we change something to hyunwok before final submit
type HybridStruct struct {
	InvitationStructUUID   uuid.UUID
	InvitationStructDECKey []byte
}

// Helper functions
/*
func (userdata *User) UUIDToFileStruct(UUID uuid.UUID) (UserFileStruct FileStruct, err error) {

}
*/

func GetUserPublicENCKey(username string) (key userlib.PKEEncKey, err error) {
	myslice := []string{username, "UserPublicENCKey"}
	UserPublicENCKeyKeyword := strings.Join(myslice, "-")
	key, ok := userlib.KeystoreGet(UserPublicENCKeyKeyword)
	if !ok {
		return key, errors.New("An error occurred while getting User Public Encryption Key" + err.Error())
	}
	return key, nil
}
func GetUserSignVerificationKey(username string) (key userlib.DSVerifyKey, err error) {
	myslice := []string{username, "UserSignVerificationKey"}
	UserSignVerificationKeyKeyword := strings.Join(myslice, "-")
	key, ok := userlib.KeystoreGet(UserSignVerificationKeyKeyword)
	if !ok {
		return key, errors.New("An error occurred while getting User DigitalSign Verification Key")
	}
	return key, nil
}
func (userdata *User) GetFileStruct(filename string) (UserFileStruct FileStruct, FileMACKey []byte, FileDECKey []byte, FileStructUUID uuid.UUID, err error) {
	// Get FileStruct of this userdata
	// 0. Make a dummy FileStruct to return with error
	var NilFileStruct FileStruct
	// CurFileStruct Settings Finished

	// NameSpace Updated well
	ChildNameSpaceStructPtr, err := userdata.GetNameSpaceStruct()
	if err != nil {
		return NilFileStruct, nil, nil, uuid.Nil, errors.New("3. An error occurred while getting NameSpaceStruct in AcceptInvitation: " + err.Error())
	}
	exist := ChildNameSpaceStructPtr.FilenameChecker(filename, userdata.Username)
	if !exist {
		return NilFileStruct, nil, nil, uuid.Nil, errors.New("3. This filename fails to exists in user's NameSpace")
	}
	// Filename Validated

	// 1. Go get the CipherNameSpace of this user
	CipherNameSpaceStructBytes, ok := userlib.DatastoreGet(userdata.NameSpaceUUID)
	if !ok {
		return NilFileStruct, nil, nil, uuid.Nil, errors.New("An error Occurred while retriving User NameSpaceStruct on NameSpaceUUID" + err.Error())
	}
	// HMACWrapperBytes of NameSpaceStruct Retrieved

	// 2. Unmarshal and Validate HMACWrapper and get Ciphertext
	EncryptedNameSpaceStructBytes, err := userdata.UnmarshalThenValidateHMACWrapperAndGetCiphertext(CipherNameSpaceStructBytes, userdata.NameSpaceMACKey)
	if err != nil {
		return NilFileStruct, nil, nil, uuid.Nil, errors.New("an error occurred while unmarshaling and validating hmacwrapper" + err.Error())
	}
	// EncryptedNameSpaceStructBytes Retrived

	// 3. Decrypt then Unmarshal to get NameSpaceStruct
	CurNameSpaceStruct, err := userdata.DecryptThenUnmarshalNameSpaceStruct(EncryptedNameSpaceStructBytes)
	if err != nil {
		return NilFileStruct, nil, nil, uuid.Nil, errors.New("an error occurred while decrypting and unmarshaling namespacestruct" + err.Error())
	}
	// userNameSpaceStruct Retrived

	// 4. Check if this file exist
	exist = CurNameSpaceStruct.FilenameChecker(filename, userdata.Username)
	if !exist {
		return NilFileStruct, nil, nil, uuid.Nil, errors.New("this filename does not exist in the user NameSpace")

	}
	// Confirmed there is this file in the NameSpace

	// 5. Get the UUID for IndicatorStruct from NameSpace
	CurFileInfo := CurNameSpaceStruct.NameSpace[filename].Dict[userdata.Username]
	CipherIndicatorStructBytesUUID := CurFileInfo.IndicatorStructUUID

	// UUID of HMACWrapperBytes of IndicatorStruct Retrived

	// 6. Get HMACWrapperBytes of IndicatorStruct
	CipherIndicatorStructBytes, ok := userlib.DatastoreGet(CipherIndicatorStructBytesUUID)
	if !ok {
		return NilFileStruct, nil, nil, FileStructUUID, errors.New("an error occurred while getting CipherindicatorStructBytes" + err.Error())
	}
	// HMACWrapperBytes of IndicatorStruct Retrieved

	// 7. Unmarshal then ValidateHMACWrapper and get ciphertext
	CurEncryptedIndicatorStructBytes, err := userdata.UnmarshalThenValidateHMACWrapperAndGetCiphertext(CipherIndicatorStructBytes, CurFileInfo.IndicatorStructMACKey)
	if err != nil {
		return NilFileStruct, nil, nil, FileStructUUID, errors.New("an error occurred while getting unmarshaling and validating hmac" + err.Error())
	}
	// EncryptedIndicatorStructBytes Retrived

	// 8. Decrypt then Unmarshal recursively to get FileStruct
	UserFileStruct, FileMACKey, FileDECKey, FileStructUUID, err = userdata.RecurseDecryptThenUnmarshalIndicatorStructUntilFileStruct(CurEncryptedIndicatorStructBytes, CurFileInfo.IndicatorStructDECKey, CurFileInfo.IndicatorStructUUID, CurFileInfo.IndicatorStructMACKey)
	if err != nil {
		return NilFileStruct, nil, nil, FileStructUUID, errors.New("an error occurred while getting recursing and decrypting " + err.Error())
	}
	/*
		// FileStruct Retrieved
		if len(FileMACKey) != 16 {
			return CurFileStruct, nil, nil, uuid.Nil, errors.New("FileMACKey out of GetFileStruct must be 16 bytes")
		}
		if len(FileDECKey) != 16 {
			return CurFileStruct, nil, nil, uuid.Nil, errors.New("FileDECKey out of GetFileStruct must be 16 bytes")
		}
	*/
	return UserFileStruct, FileMACKey, FileDECKey, FileStructUUID, nil
}
func (userdata *User) DecryptThenUnmarshalInvitationStruct(EncryptedInvitationStructBytes []byte, DECKey []byte) (UserInvitationStruct InvitationStruct, err error) {
	var NilInvitationStruct InvitationStruct
	// 1. Decrypt to get InvitationStructBytes
	UserInvitationStructBytes := userlib.SymDec(DECKey, EncryptedInvitationStructBytes)

	// 2. Unmarshal to get InvitationStruct
	err = json.Unmarshal(UserInvitationStructBytes, &UserInvitationStruct)
	if err != nil {
		return NilInvitationStruct, err
	}

	return UserInvitationStruct, nil
}
func (userdata *User) DecryptThenUnmarshalHybridStruct(PubliclyEncryptedHybridStructBytes []byte) (UserHybridStruct HybridStruct, err error) {
	var NilHybridStruct HybridStruct
	// 1. Decrypt to get HybridStructBytes
	UserHybridStructBytes, err := userlib.PKEDec(userdata.UserPublicDECKey, PubliclyEncryptedHybridStructBytes)
	if err != nil {
		return NilHybridStruct, errors.New("An error occurred while PKEDecing PubliclyEncryptedHybridStructBytes: " + err.Error())
	}

	// 2. Unmarshal to get InvitationStruct
	err = json.Unmarshal(UserHybridStructBytes, &UserHybridStruct)
	if err != nil {
		return NilHybridStruct, err
	}
	return UserHybridStruct, nil
}
func (userdata *User) DecryptThenUnmarshalFileStruct(UserEncryptedFileStructBytes []byte, DECKey []byte) (UserFileStruct FileStruct, err error) {
	// Given EncryptedFileStructBytes, return FileStruct
	var NilFileStruct FileStruct
	// 1. Decrypt EncryptedFileStructBytes with DECKey to get FileStructBytes
	CurFileStructBytes := userlib.SymDec(DECKey, UserEncryptedFileStructBytes)
	// CurFileStructBytes Settings Finished

	// 2. Unmarshal to get CurFileStruct
	var CurFileStruct FileStruct
	err = json.Unmarshal(CurFileStructBytes, &CurFileStruct)
	if err != nil {
		return NilFileStruct, nil
	}

	return CurFileStruct, nil
}
func (userdata *User) RecurseDecryptThenUnmarshalIndicatorStructUntilFileStruct(UserEncryptedIndicatorStructBytes []byte, DECKey []byte, UUID uuid.UUID, MACKeys []byte) (UserFileStruct FileStruct, FileMACKey []byte, FileDECKey []byte, FileStructUUID uuid.UUID, err error) {
	// Given EncryptedBytes, check if LastPtr is true to reach the last IndicatorStruct and then FileStruct
	// 0. Make a dummy FileStruct to return in the end
	var CurFileStruct FileStruct
	// FileStruct Settings Finished

	// 1. DecryptThenUnmarshal to get IndicatorStruct. Note that this cannot be FileStruct yet because we didn't see LastPtr == true yet
	CurIndicatorStruct, err := userdata.DecryptThenUnmarshalIndicatorStruct(UserEncryptedIndicatorStructBytes, DECKey, UUID, MACKeys)
	if err != nil {
		return CurFileStruct, nil, nil, uuid.Nil, err
	}

	// IndicatorStruct Retrieved
	var MACKey []byte
	IAMCurIndicatorToo := CurIndicatorStruct
	whileLoop := false

	// 2. Check if this is the last IndicatorStruct before FileStruct by checking if LastPtr is true
	for !CurIndicatorStruct.LastPtr {
		whileLoop = true
		MACKey = CurIndicatorStruct.FileOrNextIndicatorStructMACKey
		DECKey = CurIndicatorStruct.FileOrNextIndicatorStructDECKey
		// 2-1. If this is not the LastPtr, get the next IndicatorStructHMACWrapperBytes, MACKey, DECkey
		CurIndicatorStructBytes, ok := userlib.DatastoreGet(CurIndicatorStruct.FileOrNextIndicatorStructUUID)
		if !ok {
			return CurFileStruct, nil, nil, uuid.Nil, errors.New("An error occurred while retrieving HMACWrapperBytes of the next IndicatorStruct")
		}
		// IndicatorStructHMACWrapperBytes Retrieved

		// 2-2. UnmarshalThenValidate HMACWrapper to get EncryptedIndicatorStructBytes
		CurEncryptedIndicatorStructBytes, err := userdata.UnmarshalThenValidateHMACWrapperAndGetCiphertext(CurIndicatorStructBytes, MACKey)
		if err != nil {
			return CurFileStruct, nil, nil, uuid.Nil, err
		}
		// EncryptedIndicatorStructBytes Retrieved

		// 2-3. Decrypt then Unmarshal to get CurCurIndicatorStruct
		CurCurIndicatorStruct, err := userdata.DecryptThenUnmarshalIndicatorStruct(CurEncryptedIndicatorStructBytes, DECKey, CurIndicatorStruct.FileOrNextIndicatorStructUUID, MACKey)
		if err != nil {
			return CurFileStruct, nil, nil, uuid.Nil, err
		}
		// CurCurIndicatorStruct Settings Finished

		// 2-4. Update CurIndicatorStruct
		CurIndicatorStruct = CurCurIndicatorStruct
		// Update Finished

		if IAMCurIndicatorToo.FileOrNextIndicatorStructUUID == CurIndicatorStruct.FileOrNextIndicatorStructUUID {
		}
	}
	if whileLoop == true {
		if IAMCurIndicatorToo.FileOrNextIndicatorStructUUID == CurIndicatorStruct.FileOrNextIndicatorStructUUID {
		}
	}

	// LastPtr == true Found. This is the last Indicator Struct before FileStruct

	// 3. Get the HMACWrapperBytes of FileStruct
	CurFileStructHMACWrapperBytes, ok := userlib.DatastoreGet(CurIndicatorStruct.FileOrNextIndicatorStructUUID)
	if !ok {
		return CurFileStruct, nil, nil, uuid.Nil, errors.New("An error occurred while retrieving HMACWrapperBytes of FileStruct" + err.Error())
	}
	// HMACWrapperBytes of FileStruct Retrieved

	// 4. UnmarshalThenValidate HMACWrapper to get CurEncryptedFileStructBytes
	CurEncryptedFileStructBytes, err := userdata.UnmarshalThenValidateHMACWrapperAndGetCiphertext(CurFileStructHMACWrapperBytes, CurIndicatorStruct.FileOrNextIndicatorStructMACKey)
	if err != nil {
		return CurFileStruct, nil, nil, uuid.Nil, err
	}
	// CurEncryptedFileStructBytes Retrieved

	// 5. Decrypt then Unmarshal to get CurFileStruct
	CurFileStruct, err = userdata.DecryptThenUnmarshalFileStruct(CurEncryptedFileStructBytes, CurIndicatorStruct.FileOrNextIndicatorStructDECKey)
	if err != nil {
		return CurFileStruct, nil, nil, FileStructUUID, err
	}
	// CurFileStruct Retrieved

	return CurFileStruct, CurIndicatorStruct.FileOrNextIndicatorStructMACKey, CurIndicatorStruct.FileOrNextIndicatorStructDECKey, CurIndicatorStruct.FileOrNextIndicatorStructUUID, nil
}

func (userdata *User) EncryptWithDifferentIV(ENCKey []byte, Plaintext []byte, UUID uuid.UUID, MACKey []byte) (err error) {
	// 1. Encrypt the item again with symmetric encryption
	Cipher := userlib.SymEnc(ENCKey, userlib.RandomBytes(16), Plaintext)

	// 2. CipherWrap the newly encrypted ciphertext back to its original spot.

	err = userdata.CipherWrap(Cipher, MACKey, UUID)
	if err != nil {
		return errors.New("There is a problem with CipherWrapping to new " + err.Error())
	}

	return nil
}

func (userdata *User) DecryptThenUnmarshalIndicatorStruct(EncryptedIndicatorBytes []byte, DECKey []byte, UUID uuid.UUID, MACKey []byte) (UserIndicatorStruct IndicatorStruct, err error) {
	// Given EncryptedIndicatorStructBytes, return IndicatorStruct
	// 1. Decrypt it to get IndicatorBytes
	CurIndicatorStructBytes := userlib.SymDec(DECKey, EncryptedIndicatorBytes)
	// Decryption Complete

	// 2. Unmarshal IndicatorStructBytes to get IndicatorStruct
	var CurIndicatorStruct IndicatorStruct
	err = json.Unmarshal(CurIndicatorStructBytes, &CurIndicatorStruct)
	if err != nil {
		return CurIndicatorStruct, err
	}
	// IndicatorStruct Retrived

	// 2.5 Re-Encrypt it to the UUID
	err = userdata.EncryptWithDifferentIV(DECKey, CurIndicatorStructBytes, UUID, MACKey)
	if err != nil {
		return CurIndicatorStruct, err
	}

	return CurIndicatorStruct, nil
}
func (userdata *User) DecryptThenUnmarshalNameSpaceStruct(EncryptedNameSpaceStructBytes []byte) (UserNameSpaceStruct NameSpaceStruct, err error) {
	// Given EncryptedNameSpaceStructBytes, return NameSpaceStruct
	// 1. Decrypt it to get NameSpaceStructBytes
	CurNameSpaceStructBytes := userlib.SymDec(userdata.NameSpaceDECKEY, EncryptedNameSpaceStructBytes)
	// Decryption Complete

	// 2. Unmarshal NameSpaceStructBytes to get NameSpaceStruct
	var CurNameSpacestruct NameSpaceStruct
	err = json.Unmarshal(CurNameSpaceStructBytes, &CurNameSpacestruct)
	if err != nil {
		return CurNameSpacestruct, err
	}
	// NameSpaceStruct Retrived

	// 1.5 Re-Encrypt it to the UUID
	err = userdata.EncryptWithDifferentIV(userdata.NameSpaceDECKEY, CurNameSpaceStructBytes, userdata.NameSpaceUUID, userdata.NameSpaceMACKey)
	if err != nil {
		return CurNameSpacestruct, err
	}

	return CurNameSpacestruct, nil
}
func (userdata *User) DecryptThenUnmarshalLinkedListBlock(EncryptedLinkedListBlockBytes []byte, DECKey []byte, MACKey []byte, UUID uuid.UUID) (UserLinkedListBlock LinkedListBlock, err error) {
	// Given EncryptedLinkedListBlockBytes, return LinkedListBlock
	// 1. Decrypt it to get LinkedListBlockBytes
	CurLinkedListBlockBytes := userlib.SymDec(DECKey, EncryptedLinkedListBlockBytes)
	// Decryption Complete

	// 2. Unmarshal NameSpaceStructBytes to get NameSpaceStruct
	var CurLinkedListBlock LinkedListBlock
	err = json.Unmarshal(CurLinkedListBlockBytes, &CurLinkedListBlock)
	if err != nil {
		return CurLinkedListBlock, err
	}
	// NameSpaceStruct Retrived

	// 2.5 Re-Encrypt it to the UUID
	err = userdata.EncryptWithDifferentIV(DECKey, CurLinkedListBlockBytes, UUID, MACKey)
	if err != nil {
		return CurLinkedListBlock, err
	}

	return CurLinkedListBlock, nil
}
func (userdata *User) UnmarshalThenValidateHMACWrapperAndGetCiphertext(HMACWrapperBytes []byte, MACKey []byte) (Ciphertext []byte, err error) {
	// Given HMACWrapperBytes, Unmarshal then validate MAC with the MACKey

	// 1. Unmarshal to get HMACWrapper Structure
	var NameSpaceStructHMACWrapper HMACWrapper
	json.Unmarshal(HMACWrapperBytes, &NameSpaceStructHMACWrapper)
	// HMACWrapper of NameSpaceStruct Retrieved

	// 2. Get MAC of Ciphertext
	MAC, err := userlib.HMACEval(MACKey, NameSpaceStructHMACWrapper.Ciphertext)
	if err != nil {
		return nil, err
	}
	// MAC of Ciphertext Derived

	// 3. Compare two MACs if they are Equal
	if userlib.HMACEqual(NameSpaceStructHMACWrapper.MAC, MAC) != true {
		return nil, errors.New("An error occurred during HMACEqual of HMACWrapper components with MACKey")
	}
	// MAC Validated, Integrity of this Ciphertext Achieved

	// Return Ciphertext of this HMAC
	return NameSpaceStructHMACWrapper.Ciphertext, nil

}
func (userdata *User) GetNameSpaceStruct() (CurNameSpacestructPtr *NameSpaceStruct, err error) {
	// working assuming that user is already decrypted since we can only access if we have user + password
	//var dummyNameSpaceStructPtr	*NameSpaceStruct

	// 1. Use the NameSpaceUUID to get HMACWrapperBytes of the NameSpaceStruct
	HMACWrapperBytesOfNameSpaceStruct, ok := userlib.DatastoreGet(userdata.NameSpaceUUID)
	if ok != true {
		return nil, errors.New("An error occurred while getting a NameSpace from DatastoreGet. ")
	}
	// HMACWrapperBytesOfNameSpaceStruct settings Finished

	// 2. Unmarshal then Validate then get
	EncryptedNameSpaceBytes, err := userdata.UnmarshalThenValidateHMACWrapperAndGetCiphertext(HMACWrapperBytesOfNameSpaceStruct, userdata.NameSpaceMACKey)
	if err != nil {
		return nil, err
	}
	// EncryptedNameSpaceBytes Retrieved

	// 3. Decrypt Ciphertext of the NameSpaceStruct
	UserNameSpaceStruct, err := userdata.DecryptThenUnmarshalNameSpaceStruct(EncryptedNameSpaceBytes)
	if err != nil {
		return nil, err
	}
	UserNameSpaceStructPtr := &UserNameSpaceStruct
	// Return the dictionary of user's namespace
	return UserNameSpaceStructPtr, nil
}

func (namespacedata *NameSpaceStruct) FilenameChecker(filename string, username string) (existence bool) {
	if _, exist := namespacedata.NameSpace[filename].Dict[username]; exist {
		// There exists this filename already
		return true
	}

	// There isn't a file with this filename
	return false
}

func (UserNameSpaceStructData *NameSpaceStruct) NameSpaceFileSetter(filename string, username string, UserFileInfo FileInfo) (err error) {
	// username can be != userdata.Username when a file is shared to a child
	// Make a FileInfoDict.Dict
	var UserFileInfoDict FileInfoDict
	if UserFileInfoDict.Dict == nil {
		UserFileInfoDict.Dict = map[string]FileInfo{}
	}
	UserFileInfoDict.Dict[username] = UserFileInfo

	if UserNameSpaceStructData.NameSpace == nil {
		UserNameSpaceStructData.NameSpace = map[string]FileInfoDict{}
	}
	UserNameSpaceStructData.NameSpace[filename] = UserFileInfoDict
	exist := UserNameSpaceStructData.FilenameChecker(filename, username)
	if exist == false {
		return errors.New("An error occurred inside NameSpaceFileSetter: File settings failed" + err.Error())
	}
	return nil
}

/*
func (namespacedata *NameSpaceStruct) FilenameSetterAtRandom(filename string) (err error) {
	// 1. Check if the filename exist in user's namespace
	exist := namespacedata.FilenameChecker(filename)
	if exist == true {
		return errors.New("This filename already existed in this user: " + err.Error())
	}
	//

	// 2. Make the random UUID
	UUID := uuid.New()
	if err != nil {
		return errors.New("An error occurred while generating random new UUID: " + err.Error())
	}
	// Random UUID Completed

	// 3. Set the UUID for filename in NameSpaceDict
	namespacedata.NameSpace[filename] = UUID
	// Setting Completed

	return nil
}
*/

func MarshalThenEncryptUserStruct(userdata User, DECKey []byte) (EncryptedUserdataBytes []byte, err error) {
	// 1. Marshal User
	userdataBytes, err := json.Marshal(userdata)
	if err != nil {
		return nil, errors.New("An error occurred while serializing userCiphertext: " + err.Error())
	}

	// 2. Symmetric Encrypt User
	userCiphertext := userlib.SymEnc(userdata.SessionKey, userlib.RandomBytes(16), userdataBytes)
	return userCiphertext, nil
}

func (userdata *User) MarshalThenEncryptLinkedListBlock(CurLinkedListBlock LinkedListBlock, DECKey []byte) (EncryptedLinkedListBlockBytes []byte, err error) {
	// 1. Marshal LinkedListBlock
	LinkedListBlockBytes, err := json.Marshal(CurLinkedListBlock)
	if err != nil {
		return nil, errors.New("An error occurred while serializing CurLinkedListBlock: " + err.Error())
	}

	// 2. Symmetric Encrypt LinkedListBlockBytes
	EncryptedLinkedListBlock := userlib.SymEnc(DECKey[:16], userlib.RandomBytes(16), LinkedListBlockBytes)
	return EncryptedLinkedListBlock, nil
}
func (userdata *User) MarshalThenEncryptFileStruct(CurFileStruct FileStruct, MACKey []byte, DECKey []byte) (EncryptedFileStructBytes []byte, err error) {
	// 1. Marshal FileStruct
	FileStructBytes, err := json.Marshal(CurFileStruct)
	if err != nil {
		return nil, errors.New("An error occurred while serializing CurFileStruct: " + err.Error())
	}

	// 2. Symmetric Encrypt FileStructBytes
	EncryptedFileStruct := userlib.SymEnc(DECKey[:16], userlib.RandomBytes(16), FileStructBytes)
	return EncryptedFileStruct, nil
}
func (userdata *User) MarshalThenEncryptIndicatorStruct(CurIndicatorStruct IndicatorStruct) (EncryptedIndicatorStructBytes []byte, MACKey []byte, DECKey []byte, err error) {
	// 0. Generate MACKey and DECKey for this IndicatorStruct
	originalKey := userlib.RandomBytes(16)
	MACKey, err = userlib.HashKDF(originalKey, []byte("indicator-mac-key"))
	if err != nil {
		return nil, nil, nil, errors.New("An error occurred while using HashKDF to make MACKey: " + err.Error())
	}
	MACKey = MACKey[:16]
	DECKey, err = userlib.HashKDF(MACKey[:16], []byte("indicator-dec-key"))
	if err != nil {
		return nil, nil, nil, errors.New("An error occurred while using HashKDF to make DECKey: " + err.Error())
	}
	DECKey = DECKey[:16]

	// 1. Marshal IndicatorStruct
	IndicatorStructBytes, err := json.Marshal(CurIndicatorStruct)
	if err != nil {
		return nil, nil, nil, errors.New("An error occurred while serializing CurFileStruct: " + err.Error())
	}

	// 2. Symmetric Encrypt IndicatorStructBytes
	EncryptedIndicatorStruct := userlib.SymEnc(DECKey[:16], userlib.RandomBytes(16), IndicatorStructBytes)
	return EncryptedIndicatorStruct, MACKey, DECKey, nil
}

func (userdata *User) MarshalThenEncryptIndicatorStructWithKeys(CurIndicatorStruct IndicatorStruct, DECKey []byte) (EncryptedIndicatorStructBytes []byte, err error) {

	// 1. Marshal IndicatorStruct
	IndicatorStructBytes, err := json.Marshal(CurIndicatorStruct)
	if err != nil {
		return nil, errors.New("An error occurred while serializing CurFileStruct: " + err.Error())
	}

	// 2. Symmetric Encrypt IndicatorStructBytes
	EncryptedIndicatorStruct := userlib.SymEnc(DECKey, userlib.RandomBytes(16), IndicatorStructBytes)
	return EncryptedIndicatorStruct, nil
}

func (userdata *User) MarshalThenEncryptInvitationStruct(struc InvitationStruct, DECKey []byte) (EncryptedUserInvitationBytes []byte, err error) {
	// Given InvitationStruct, return Ciphertext for HMACWrapper

	// 1. Marshal
	UserInvitationBytes, err := json.Marshal(struc)
	if err != nil {
		return nil, errors.New("An error occurred while serializing UserInvitationBytes: " + err.Error())
	}
	// Marshal Finished

	// 2. Encrypt
	EncryptedUserInvitationBytes = userlib.SymEnc(DECKey, userlib.RandomBytes(16), UserInvitationBytes)
	return EncryptedUserInvitationBytes, nil
}
func (userdata *User) MarshalThenEncryptHybridStruct(struc HybridStruct, ENCKey userlib.PKEEncKey) (EncryptedChildHybridStructBytes []byte, err error) {
	// Given InvitationStruct, return Ciphertext for HMACWrapper

	// 1. Marshal
	UserHybridStructBytes, err := json.Marshal(struc)
	if err != nil {
		return nil, errors.New("An error occurred while serializing UserHybridStructBytes: " + err.Error())
	}
	// Marshal Finished

	// 2. Public Encryption
	EncryptedChildHybridStructBytes, err = userlib.PKEEnc(ENCKey, UserHybridStructBytes)
	if err != nil {
		return nil, errors.New("An error occurred during public encryption of UserHybridStructBytes: " + err.Error())
	}
	// Public Encryption Finished
	return EncryptedChildHybridStructBytes, nil
}
func (userdata *User) MarshalThenEncryptNameSpaceStruct(CurNameSpaceStruct NameSpaceStruct) (EncryptedNameSpaceStructBytes []byte, err error) {
	// 1. Marshal NameSpaceStruct
	NameSpaceStructBytes, err := json.Marshal(CurNameSpaceStruct)
	if err != nil {
		return nil, errors.New("An error occurred while serializing CurNameSpaceStruct: " + err.Error())
	}

	// 2. Symmetric Encrypt NameSpaceStructByte
	EncryptedNameSpaceStruct := userlib.SymEnc(userdata.NameSpaceDECKEY[:16], userlib.RandomBytes(16), NameSpaceStructBytes)
	return EncryptedNameSpaceStruct, nil
}
func CipherWrapWithoutUserdata(struc []byte, UUID uuid.UUID, MACKey []byte) (err error) {
	// struc: Encrypted, Marshaled, source structure []byte we are going to make CiphertextHMAC out of.
	// Goal: Make HMACWrapperForEveryStruct out of any Encrypted Marshaled structure bytes
	var Cipher HMACWrapper
	Cipher.Ciphertext = struc
	Cipher.MAC, err = userlib.HMACEval(MACKey[:16], Cipher.Ciphertext)
	if err != nil {
		return errors.New("An error occurred while evaluating HMAC of userCiphertext: " + err.Error())
	}

	serializedCiphertext, err := json.Marshal(Cipher)
	if err != nil {
		return errors.New("An error occurred while serializing userCiphertext: " + err.Error())
	}
	userlib.DatastoreSet(UUID, serializedCiphertext)

	return nil
}
func (userdata *User) CipherWrap(struc []byte, MACKey []byte, UUID uuid.UUID) (err error) {
	// struc: Encrypted, Marshaled, source structure []byte we are going to make CiphertextHMAC out of.
	// Goal: Make HMACWrapperForEveryStruct out of any Encrypted Marshaled structure bytes
	var Cipher HMACWrapper
	Cipher.Ciphertext = struc
	Cipher.MAC, err = userlib.HMACEval(MACKey[:16], Cipher.Ciphertext)
	if err != nil {
		return errors.New("An error occurred while evaluating HMAC of userCiphertext: " + err.Error())
	}

	serializedCiphertext, err := json.Marshal(Cipher)
	if err != nil {
		return errors.New("An error occurred while serializing userCiphertext: " + err.Error())
	}
	userlib.DatastoreSet(UUID, serializedCiphertext)

	return nil
}

func (userdata *User) CipherWrapAtSomewhereRandom(struc []byte, MACKey []byte) (CipherUUID uuid.UUID, err error) {
	// struc: Encrypted, Marshaled, source structure []byte we are going to make CiphertextHMAC out of.
	// Goal: Make HMACWrapperForEveryStruct out of any Encrypted Marshaled structure bytes
	var Cipher HMACWrapper
	Cipher.Ciphertext = struc
	Cipher.MAC, err = userlib.HMACEval(MACKey[:16], Cipher.Ciphertext)
	if err != nil {
		return uuid.New(), errors.New("An error occurred while evaluating HMAC of userCiphertext: " + err.Error())
	}

	serializedCiphertext, err := json.Marshal(Cipher)
	if err != nil {
		return uuid.New(), errors.New("An error occurred while serializing userCiphertext: " + err.Error())
	}
	UUID := uuid.New()
	userlib.DatastoreSet(UUID, serializedCiphertext)

	return UUID, nil
}
func (userdata *User) CipherUpdateNameSpaceStruct(CurNameSpaceStruct NameSpaceStruct) (err error) {
	// Update HMACWrapper of NameSpaceStruct

	// 1. Marshal then Encrypt CurNameSpaceStruct
	EncryptedNameSpaceStructBytes, err := userdata.MarshalThenEncryptNameSpaceStruct(CurNameSpaceStruct)
	if err != nil {
		return err
	}
	// Marshal then Encrypt NameSpaceStruct Finished

	// 2. Get the UUID of the NameSpaceStruct
	NameSpaceStructUUID := userdata.NameSpaceUUID
	// UUID of the NameSpaceStruct Finished

	// 3. Get the MAC out of EncryptedNameSpaceStructBytes
	MAC, err := userlib.HMACEval(userdata.NameSpaceMACKey, EncryptedNameSpaceStructBytes)
	if err != nil {
		return err
	}
	// MAC Constructed

	// 4. Construct HMACWrapper for Ciphertext of NameSpaceStruct and its MAC
	var NameSpaceStructHMACWrapper HMACWrapper
	NameSpaceStructHMACWrapper.Ciphertext = EncryptedNameSpaceStructBytes
	NameSpaceStructHMACWrapper.MAC = MAC
	// HMACWrapper Finished

	// 5. Marshal HMACWrapper before DataStore it
	NameSpaceStructHMACWrapperBytes, err := json.Marshal(NameSpaceStructHMACWrapper)
	if err != nil {
		return err
	}
	// Bytes are made for DataStore

	// 6. DataStore the HMACWrapperBytes
	userlib.DatastoreSet(NameSpaceStructUUID, NameSpaceStructHMACWrapperBytes)
	// DataStore Completed

	return nil
}
func (userdata *User) CipherUpdateFileStruct(CurFileStruct FileStruct, MACKey []byte, DECKey []byte, FileStructUUID uuid.UUID, filename string) (err error) {
	// Update HMACWrapper of FileStruct
	/*
		UserNameSpaceStruct, err := userdata.GetNameSpaceStruct()
		_ = UserNameSpaceStruct
		if err != nil {
			return err
		}*/

	// 1. Marshal then Encrypt CurFileStruct
	// I don't know if these are the right keys to use
	EncryptedFileStructBytes, err := userdata.MarshalThenEncryptFileStruct(CurFileStruct, MACKey, DECKey)
	if err != nil {
		return err
	}
	// Marshal then Encrypt CurFileStruct Finished

	// 2. Get the MAC out of EncryptedFileStructBytes
	MAC, err := userlib.HMACEval(MACKey, EncryptedFileStructBytes)
	if err != nil {
		return err
	}
	// MAC Constructed

	// 4. Construct HMACWrapper for Ciphertext of FileStruct and its MAC
	var FileStructHMACWrapper HMACWrapper
	FileStructHMACWrapper.Ciphertext = EncryptedFileStructBytes
	FileStructHMACWrapper.MAC = MAC
	// HMACWrapper Finished

	// 5. Marshal HMACWrapper before DataStore it
	FileStructHMACWrapperBytes, err := json.Marshal(FileStructHMACWrapper)
	if err != nil {
		return err
	}
	// Bytes are made for DataStore

	// 6. DataStore the HMACWrapperBytes
	userlib.DatastoreSet(FileStructUUID, FileStructHMACWrapperBytes)
	// DataStore Completed

	return nil
}

func (userdata *User) GetIndicatorStructUUIDForFileInfo(filename string) (UUID uuid.UUID, err error) {
	return uuid.FromBytes(userlib.Hash([]byte(userdata.Username + string(userdata.SecretSaltForFileNames) + filename))[:16])
}
func (userdata *User) UUIDToLinkedListBlock(HMACWrapperBytesUUID uuid.UUID, MACKey []byte, DECKey []byte) (UserLinkedListBlock LinkedListBlock, err error) {
	// Given UUID of HMACWrapperBytes of LinkedListBlock, return LinkedListBlock
	// 1. Get the HMACWrapperBytes of LinkedListBlock by UUID
	HMACWrapperBytesOfLinkedListBlock, ok := userlib.DatastoreGet(HMACWrapperBytesUUID)
	if !ok {
		return UserLinkedListBlock, errors.New("An error occurred while getting HMACWrapperBytesOfLinkedListBlock: " + err.Error())
	}
	// HMACWrapperBytesOfLinkedListBlock Retrieved

	// 2. UnmarshalThenValidate to get EncryptedLinkedListBlockBytes
	UserEncryptedLinkedListBlockBytes, err := userdata.UnmarshalThenValidateHMACWrapperAndGetCiphertext(HMACWrapperBytesOfLinkedListBlock, MACKey)
	if err != nil {
		return UserLinkedListBlock, errors.New("An error occurred while getting UserEncryptedLinkedListBlockBytes: " + err.Error())
	}
	// UserEncryptedLinkedListBlockBytes Retrieved

	// 3. DecryptThenUnmarshal to get LinkedListBlock
	UserLinkedListBlock, err = userdata.DecryptThenUnmarshalLinkedListBlock(UserEncryptedLinkedListBlockBytes, DECKey, MACKey, HMACWrapperBytesUUID)
	if err != nil {
		return UserLinkedListBlock, errors.New("An error occurred while decrypting and unmarshaling LinkedListBlock: " + err.Error())
	}
	// LinkedListBlock Retrieved

	return UserLinkedListBlock, nil
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdata.Username = username
	SignKey, VerifyKey, err := userlib.DSKeyGen()

	if err != nil {
		return nil, errors.New("An error occurred while generating a Digital Signature: " + err.Error())
	}
	userdata.UserSignKey = SignKey
	myslice := []string{username, "UserSignVerificationKey"}
	UserSignVerificationKeyKeyword := strings.Join(myslice, "-")
	userlib.KeystoreSet(UserSignVerificationKeyKeyword, VerifyKey) // VerifyKey is stored inside KeyStore in public

	userdata.SecretSaltForFileNames, err = userlib.HashKDF(userlib.RandomBytes(16), []byte("Secret-Salt-For-Filenames"))
	if err != nil {
		return nil, errors.New("An error occurred while generating a user SecretSalt: " + err.Error())
	}

	// Generate and Store Public and Secret Key pair
	UserENCKey, UserDECKey, err := userlib.PKEKeyGen()
	_ = UserDECKey
	if err != nil {
		return nil, errors.New("An error occurred while generating a Public Encryption Key pair: " + err.Error())
	}
	userdata.UserPublicDECKey = UserDECKey
	// userdata.UserDecKey = UserDecKey
	myslice = []string{username, "UserPublicENCKey"}
	UserPublicENCKeyKeyword := strings.Join(myslice, "-")
	_, okay := userlib.KeystoreGet(UserPublicENCKeyKeyword)
	if okay {
		return nil, errors.New("Username already exists.")
	}
	userlib.KeystoreSet(UserPublicENCKeyKeyword, UserENCKey) // PKEEncKey is stored inside KeyStore

	// Setup User Password (ArgonKey) with salt
	salt := []byte(username)
	ArgonKey := userlib.Argon2Key([]byte(password), salt, 16)
	// Do not save ArgonKey inside User. Verify with HMAC of SessionKey instead
	// SessionKey is deterministic. It can decrypt User Ciphertext
	// SessionKey is made by ArgonKey
	SessionKey, err := userlib.HashKDF(ArgonKey, []byte("Derive SessionKey from ArgonKey"))
	if err != nil {
		return nil, errors.New("An error occurred while deriving SessionKey out of ArgonKey: " + err.Error())
	}
	SessionKey = SessionKey[:16]
	userdata.SessionKey = SessionKey

	/* We don't store IndicatorKeys in userdata anymore. It belongs to FileInfo of NameSpace inside NameSpaceStruct. Refer to NameSpaceStruct.

	// First 16 bytes of hashed SessionKey is Indicator key
	IndicatorKey, err := userlib.HashKDF(SessionKey, []byte("Derive IndicatorKey from SessionKey"))
	if err != nil {
		return nil, errors.New("An error occurred while deriving IndicatorKey out of SessionKey: " + err.Error())
	}
	// Store IndicatorKey to User
	userdata.IndicatorStructMACKey = IndicatorKey[32:48]
	userdata.IndicatorStructDECKey = IndicatorKey[16:32]
	*/

	// MACKey is made by SessionKey, 16 bytes
	MACKey, err := userlib.HashKDF(SessionKey, []byte("Derive MACKey from SessionKey"))
	if err != nil {
		return nil, errors.New("An error occurred while deriving MACKey out of SessionKey: " + err.Error())
	}
	MACKey = MACKey[:16]
	userdata.MACKey = MACKey

	/*
		// Make NameSpaceUUID from random UUID
		userdata.NameSpaceUUID = uuid.New() // need to set something in DataStore in this location
		// gives us a random uuid, but later when we get namespacestructure, we haven't put anything we just have a uuid

		// Generate NameSpaceKeys from SessionKey
		NameSpaceKeys, err := userlib.HashKDF(SessionKey, []byte("Derive NameSpaceKeys from SessionKey"))
		if err != nil {
			return nil, errors.New("An error occurred while deriving NameSpaceKeys out of SessionKey: " + err.Error())
		}

		// Generate NameSpaceDecKey and NameSpaceMacKey from NameSpaceKeys
		userdata.NameSpaceDECKEY = NameSpaceKeys[:16]
		userdata.NameSpaceMACKey = NameSpaceKeys[16:32]

		// Marshal then encrypt a currently empty namespace struct

	*/

	// Generate a NameSpaceUUID from random UUID
	userdata.NameSpaceUUID = uuid.New()

	// Generate NameSpaceKeys from SessionKey
	NameSpaceKeys, err := userlib.HashKDF(SessionKey, []byte("Derive NameSpaceKeys from SessionKey"))
	if err != nil {
		return nil, errors.New("An error occurred while deriving NameSpaceKeys out of SessionKey: " + err.Error())
	}

	// Generate NameSpaceDecKey and NameSpaceMacKey from NameSpaceKeys
	userdata.NameSpaceDECKEY = NameSpaceKeys[:16]
	userdata.NameSpaceMACKey = NameSpaceKeys[16:32]

	var EmptyNameSpaceStruct NameSpaceStruct
	/*
		var DummyFileInfo FileInfo
		var DummyFileInfoDict FileInfoDict
		DummyFileInfoDict.Dict["dummy"] = DummyFileInfo
		EmptyNameSpaceStruct.NameSpace["dummy"] = DummyFileInfoDict
		// make(map[string]FileInfoDict{})
	*/
	EncryptedNameSpaceStructBytes, err := userdata.MarshalThenEncryptNameSpaceStruct(EmptyNameSpaceStruct)
	if err != nil {
		return nil, errors.New("An error occurred while Marshal then encrypt NameSpaceStruct" + err.Error())
	}

	err = userdata.CipherWrap(EncryptedNameSpaceStructBytes, userdata.NameSpaceMACKey, userdata.NameSpaceUUID)
	if err != nil {
		return nil, errors.New("An error occurred while cipherwrapping namespace: " + err.Error())
	}

	// Marshal then Encrypt User Struct
	EncUserStructBytes, err := MarshalThenEncryptUserStruct(userdata, ArgonKey)
	if err != nil {
		return nil, errors.New("An error occurred while marshaling then encrypting user struct: " + err.Error())
	}

	// Get User UUID by deterministically appending hash of username and hash of password, get UUID from UUID, then CipherWrap
	UserBytes := append(userlib.Hash([]byte(username)), userlib.Hash([]byte(password))...)
	UserDataUUID, err := uuid.FromBytes(UserBytes[:16])
	if err != nil {
		return nil, errors.New("An error occurred while creating UUID of User from: " + err.Error())
	}
	err = CipherWrapWithoutUserdata(EncUserStructBytes, UserDataUUID, userdata.MACKey)
	if err != nil {
		return nil, errors.New("An error occurred while cipherwrapping user from: " + err.Error())
	}
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	/*
		var userdata User
		userdataptr = &userdata
	*/
	// 1. Get User UUID by deterministically appending hash of username and hash of password
	UserBytes := append(userlib.Hash([]byte(username)), userlib.Hash([]byte(password))...)
	UserDataUUID, err := uuid.FromBytes(UserBytes[:16])
	if err != nil {
		return nil, errors.New("An error occurred while creating UUID of User from: " + err.Error())
	}
	CipherWrapUserData, ok := userlib.DatastoreGet(UserDataUUID)
	if !ok {
		return nil, errors.New("An error occurred while getting UserDataUUID from Datastore: ")
	}

	// 2. Unmarshal CipherWrapUserData to get HMACWrapper structure
	var CipherWrapUserStruct HMACWrapper
	err = json.Unmarshal(CipherWrapUserData, &CipherWrapUserStruct)
	if err != nil {
		return nil, errors.New("An error occurred while unmarshaling CipherWrapUserStruct: " + err.Error())
	}

	// 3. Get MACKey the same way as InitUser
	// Setup User Password (ArgonKey) with salt
	salt := []byte(username)
	ArgonKey := userlib.Argon2Key([]byte(password), salt, 16)
	// Do not save ArgonKey inside User. Verify with HMAC of SessionKey instead
	// SessionKey is deterministic. It can decrypt User Ciphertext
	// SessionKey is made by ArgonKey
	SessionKey, err := userlib.HashKDF(ArgonKey, []byte("Derive SessionKey from ArgonKey"))
	if err != nil {
		return nil, errors.New("An error occurred while deriving SessionKey out of ArgonKey: " + err.Error())
	}
	SessionKey = SessionKey[:16]

	// 4. MACKey is made by SessionKey, 16 bytes
	MACKey, err := userlib.HashKDF(SessionKey, []byte("Derive MACKey from SessionKey"))
	if err != nil {
		return nil, errors.New("An error occurred while deriving MACKey out of SessionKey: " + err.Error())
	}
	MACKey = MACKey[:16]

	// 5. Check if HMAC is equal
	CipherWrapHMAC, err := userlib.HMACEval(MACKey, CipherWrapUserStruct.Ciphertext)
	success := userlib.HMACEqual(CipherWrapHMAC, CipherWrapUserStruct.MAC)
	if success != true {
		return nil, errors.New("An error occurred because HMAC does not match, meaning MITM attack: " + err.Error())
	}

	// 6. Decrypt User structure from CipherWrap Struct
	UserStructByte := userlib.SymDec(SessionKey, CipherWrapUserStruct.Ciphertext)
	// continue here

	// 7. Unmarshal the UserStructByte to get the User Struct back and assign it to userdataptr
	var userdata User
	err = json.Unmarshal(UserStructByte, &userdata)
	if err != nil {
		return nil, errors.New("An error occurred while unmarshaling user structure: " + err.Error())
	}
	userdataptr = &userdata

	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {

	// 1. Make a MACKey for this file
	originalKey := userlib.RandomBytes(16)
	FileMACKey, err := userlib.HashKDF(originalKey, []byte("file-mac-key"))
	if err != nil {
		return err
	}
	FileMACKey = FileMACKey[:16]
	// FileMACKey Finished

	// 2. Make a DECKey for this file
	FileDECKey, err := userlib.HashKDF(FileMACKey[:16], []byte("file-dec-key"))
	if err != nil {
		return err
	}
	FileDECKey = FileDECKey[:16]
	// FileDECKey Finished
	// Two Keys will be stored inside FileStruct

	// 3. Encrypt content for integrity
	CipherContent := userlib.SymEnc(FileDECKey, userlib.RandomBytes(16), content)

	// 4. Wrap content with MACKey and random UUID
	HMACWrapperOfContentUUID, err := userdata.CipherWrapAtSomewhereRandom(CipherContent, FileMACKey) // Check again, should take in structure, not the keys?
	if err != nil {
		return err
	}
	// HMACWrapperOfContentUUID is the HMACWrapper of content with MACKey
	// Finished

	// 5. Make a new LinkedListBlock
	var CurLinkedListBlock LinkedListBlock
	CurLinkedListBlock.ContentUUID = HMACWrapperOfContentUUID
	CurLinkedListBlock.LastPtr = true
	// CurLinkedListBlock Settings Finished
	// CurLinkedListBlock is a block points to HMACWrapperOfContent and Next LinkedListBlock

	// 6. Make CurLinkedListBlock into a Ciphertext.
	CipherCurLinkedListBlock, err := userdata.MarshalThenEncryptLinkedListBlock(CurLinkedListBlock, FileDECKey)
	if err != nil {
		return err
	}

	// Ciphertext Finished

	// 7. Wrap LinkedListBlock with MACKey and random UUID
	LinkedListBlockUUID, err := userdata.CipherWrapAtSomewhereRandom(CipherCurLinkedListBlock, FileMACKey)
	if err != nil {
		return err
	}

	// CipherWrapperOfLinkedListBlock finished

	// 8. Make a new FileStruct
	var CurFileStruct FileStruct
	CurFileStruct.HeadPtr = LinkedListBlockUUID
	CurFileStruct.TailPtr = LinkedListBlockUUID

	// CurFileStruct Settings Finished

	// 9. Make the FileStruct into Ciphertext by Marshal then Encrypt with FileMACKey and FileDECKey
	CipherCurFileStruct, err := userdata.MarshalThenEncryptFileStruct(CurFileStruct, FileMACKey, FileDECKey)
	if err != nil {
		return err
	}
	// CipherCurFileStruct Settings Finished

	// 10. Wrap CipherCurFileStruct and its MAC with a Wrapper
	FileStructUUID, err := userdata.CipherWrapAtSomewhereRandom(CipherCurFileStruct, FileMACKey)
	if err != nil {
		return err
	}
	// HMACWrapper for CipherCurFileStruct and its MAC setting finished.

	// 11. Make a IndicatorStruct for the HMACWrapper of FileStruct
	CurIndicatorStruct := IndicatorStructMaker(FileMACKey, FileDECKey, FileStructUUID, true)
	// IndicatorStruct settings Finished

	// 12. Make the IndicatorStruct into Ciphertext by Marshal then Encrypt with user's IndicatorStructMACKey and IndicatorStructDECKey
	CipherCurIndicatorStruct, IndicatorStructMACKey, IndicatorStructDECKey, err := userdata.MarshalThenEncryptIndicatorStruct(CurIndicatorStruct)
	if len(IndicatorStructMACKey) != 16 {
		return errors.New("IndicatorStructMACKey is not 16 bytes")
	}
	if len(IndicatorStructDECKey) != 16 {
		return errors.New("IndicatorStructDECKey is not 16 bytes")
	}
	if err != nil {
		return err
	}
	// CipherCurIndicatorStruct settings Finished

	// 13. Make UUID for FileInfo inside the namespace
	CipherCurIndicatorStructUUID, err := userdata.GetIndicatorStructUUIDForFileInfo(filename)
	if err != nil {
		return err
	}
	// UUID for CipherCurIndicatorStruct Settings Finished

	// 14. Store HMACWrapper for CipherCurFileStruct UUID at the Indicator Struct
	err = userdata.CipherWrap(CipherCurIndicatorStruct, IndicatorStructMACKey, CipherCurIndicatorStructUUID)
	if err != nil {
		return err
	}
	// CipherCurIndicatorStruct DataStore Finished

	// 15. Get NameSStructpace of this User
	CurNameSpaceStructPtr, err := userdata.GetNameSpaceStruct()
	if err != nil {
		return err
	}
	// Getting NameSpaceStruct Finished

	// 16. Make the FileInfo Struct to be placed inside NameSpace inside NameSpaceStruct. It doesn't have to be marshaled or encrypted
	var CurFileInfo FileInfo
	CurFileInfo.IndicatorStructUUID = CipherCurIndicatorStructUUID
	CurFileInfo.IndicatorStructMACKey = IndicatorStructMACKey
	CurFileInfo.IndicatorStructDECKey = IndicatorStructDECKey

	// 16. Set the key: value pair in NameSpace in CurNameSpaceStruct
	var CurFileInfoDict FileInfoDict
	CurFileInfoDict.Dict = map[string]FileInfo{}
	CurFileInfoDict.Dict[userdata.Username] = CurFileInfo
	CurNameSpaceStructPtr.NameSpace = map[string]FileInfoDict{}
	CurNameSpaceStructPtr.NameSpace[filename] = CurFileInfoDict
	// Setting the filename: UUID pair in NameSpace of this user Finished

	// 17. CipherUpdate to update HMAC of changed NameSpaceStruct
	err = userdata.CipherUpdateNameSpaceStruct(*CurNameSpaceStructPtr)
	if err != nil {
		return err
	}
	// NameSpaceStruct Wrapper Updated

	// 18. Did we succeed? Let's see if the file exists
	exist := CurNameSpaceStructPtr.FilenameChecker(filename, userdata.Username)
	if !exist {
		return errors.New("File doesn't exist: " + err.Error())
	}
	// There exists this filename!
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// file existence will be checked inside GetFileStruct
	// 0. Get the Child's NameSpace to check the filenames
	ChildNameSpaceStructPtr, err := userdata.GetNameSpaceStruct()
	if err != nil {
		return errors.New("4. An error occurred while getting NameSpaceStruct in AcceptInvitation: " + err.Error())
	}
	exist := ChildNameSpaceStructPtr.FilenameChecker(filename, userdata.Username)
	if !exist {
		return errors.New("4. This filename doesn't exists in your NameSpace")
	}
	// Filename Validated

	// 1. Get FileStruct
	CurFileStruct, FileMACKey, FileDECKey, FileStructUUID, err := userdata.GetFileStruct(filename)
	if err != nil {
		return errors.New("5. This filename doesn't exists in your NameSpace")
	}
	// FileStruct Settings Finished. CurFileStructPtr is a pointer to FileStruct. Use *CurFileStructPtr to access FileStruct

	// 2. Go get the HMACWrapperBytes of TailLinkedListBlock
	TailLinkedListBlockHMACWrapperBytes, ok := userlib.DatastoreGet(CurFileStruct.TailPtr)
	if ok != true {
		return errors.New("an error occurred while retrieving HMACWrapperBytes of TailLinkedListBlock In AppendFile")
	}
	// HMACWrapperBytes Retrieved

	// 3. Unmarshal and Validate to get EncryptedTailLinkedListBlockBytes
	CurEncryptedTailLinkedListBlockBytes, err := userdata.UnmarshalThenValidateHMACWrapperAndGetCiphertext(TailLinkedListBlockHMACWrapperBytes, FileMACKey)
	if err != nil {
		return err
	}
	// EncryptedTailLinkedBlockBytes Retrieved

	// 4. DecryptThenUnmarshalLinkedListBlock to get TailLinkedListBlock
	TailLinkedListBlock, err := userdata.DecryptThenUnmarshalLinkedListBlock(CurEncryptedTailLinkedListBlockBytes, FileDECKey, FileMACKey, CurFileStruct.TailPtr)
	if err != nil {
		return err
	}
	// TailLinkedListBlock Retrieved

	// 5. Make content HMACWrapper for the new content
	// Encrypt content for integrity
	CipherContent := userlib.SymEnc(FileDECKey[:16], userlib.RandomBytes(16), content)

	// 6. Wrap content with MACKey and random UUID
	HMACWrapperOfContentUUID, err := userdata.CipherWrapAtSomewhereRandom(CipherContent, FileMACKey)
	if err != nil {
		return err
	}
	// HMACWrapperOfContentUUID is the HMACWrapper of content with MACKey
	// ContentHMACWrapper Finished

	// 7. Make LinkedListBlock
	var CurLinkedListBlock LinkedListBlock
	CurLinkedListBlock.ContentUUID = HMACWrapperOfContentUUID
	CurLinkedListBlock.NextUUID = uuid.Nil
	CurLinkedListBlock.LastPtr = true
	// CurLinkedListBlock will be placed next to TailLinkedListBlock

	// 8. Marshal Then Encrypt with FileDECKey
	EncryptedLinkedListBlockBytes, err := userdata.MarshalThenEncryptLinkedListBlock(CurLinkedListBlock, FileDECKey)
	if err != nil {
		return err
	}
	// Encryption and Marshal for LinkedListBlock Finished

	// 9. Wrap EncryptedLinkedListBlockBytes with HMACWrapper
	HMACWrapperOfLinkedListUUID, err := userdata.CipherWrapAtSomewhereRandom(EncryptedLinkedListBlockBytes, FileMACKey)
	if err != nil {
		return err
	}
	// HMACWrapperOfLinkedList Set on UUID

	// 10. Modify NextUUID of TailLinkedList and TailPtr of FileStruct
	TailLinkedListBlock.NextUUID = HMACWrapperOfLinkedListUUID
	TailLinkedListBlock.LastPtr = false
	// TailLinkedListBlock Updated

	// 11. Marshal Then Encrypt TailLinkedListBlock to get EncryptedTailLinkedListBlockBytes
	EncryptedTailLinkedListBlockBytes, err := userdata.MarshalThenEncryptLinkedListBlock(TailLinkedListBlock, FileDECKey)
	if err != nil {
		return err
	}

	// 12. CipherWrap EncryptedTailLinkedListBlockBytes
	err = userdata.CipherWrap(EncryptedTailLinkedListBlockBytes, FileMACKey, CurFileStruct.TailPtr)
	if err != nil {
		return err
	}

	// CipherWrap at the same UUID Succeeded

	// 13. Update TailPtr of CurFileStruct
	CurFileStruct.TailPtr = HMACWrapperOfLinkedListUUID
	// TailPtr Set

	// 14. CipherUpdate FileStruct
	err = userdata.CipherUpdateFileStruct(CurFileStruct, FileMACKey, FileDECKey, FileStructUUID, filename)
	if err != nil {
		return err
	}

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// Get FileStruct and traverse LinkedListBlocks until the TailPtr
	// file existence will be checked inside GetFileStruct

	// 1. Get FileStruct
	CurFileStruct, FileMACKey, FileDECKey, FileStructUUID, err := userdata.GetFileStruct(filename)
	if err != nil {
		return nil, errors.New("Failed to get FileStruct in LoadFile: " + err.Error())
	}

	// FileStruct Retrieved
	CurLinkedListBlockUUID := FileStructUUID // Dummy Command to Calm down FileStructUUID
	CurLinkedListBlockUUID = CurFileStruct.HeadPtr

	// 2. Get LinkedListBlock
	CurLinkedListBlock, err := userdata.UUIDToLinkedListBlock(CurFileStruct.HeadPtr, FileMACKey, FileDECKey)
	if err != nil {
		return nil, errors.New("Failed to get LinkedListBlock from UUID in LoadFile: " + err.Error())
	}
	// First LinkedListBlock Retrieved

	// 3. Get the HMACWrapperOfContent of this LinkedListBlock
	HMACWrapperOfCurContentBytes, ok := userlib.DatastoreGet(CurLinkedListBlock.ContentUUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	// HMACWrapperOfCurContentBytes Retrieved

	// 3. Unmarshal then Validate then get EncryptedContentBytes
	EncryptedContent, err := userdata.UnmarshalThenValidateHMACWrapperAndGetCiphertext(HMACWrapperOfCurContentBytes, FileMACKey)
	if err != nil {
		return nil, errors.New("Failed to Unmarshal then Validate HMACWrapper in LoadFile: " + err.Error())
	}
	// EncryptedContent Retrieved

	// 4. Decrypt to get CurContent (No need to Unmarshal since content is []byte already)
	CurContent := userlib.SymDec(FileDECKey, EncryptedContent)
	// CurContent Retrieved

	// 4.5 Re-Encrypt it to the UUID
	err = userdata.EncryptWithDifferentIV(FileDECKey, CurContent, CurLinkedListBlock.ContentUUID, FileMACKey) //come back to fix
	if err != nil {
		return nil, errors.New("Failed to encrypt it with different IV in LoadFile: " + err.Error())
	}

	// 5. Append CurContent to content
	content = append(content, CurContent...)

	// 6. Setup a While loop Starting from Getting Next LinkedListBlock UUID, Next LinkedListBlock to getting content and append

	for CurLinkedListBlockUUID != CurFileStruct.TailPtr {
		// 6-0. Go to the next LinkedListBlock
		CurLinkedListBlockUUID = CurLinkedListBlock.NextUUID
		CurLinkedListBlock, err = userdata.UUIDToLinkedListBlock(CurLinkedListBlockUUID, FileMACKey, FileDECKey)
		if err != nil {
			return nil, errors.New("Failed to get the next LinkedListBlock in while loop in LoadFile: " + err.Error())
		}
		// Next LinkedListBlock and its content Retrieved

		// 6-1. Get the HMACWrapperOfContent of this LinkedListBlock
		HMACWrapperOfCurContentBytes, ok := userlib.DatastoreGet(CurLinkedListBlock.ContentUUID)
		if !ok {
			return nil, errors.New(strings.ToTitle("file not found"))
		}
		// HMACWrapperOfCurContentBytes Retrieved

		// 6-2. Unmarshal then Validate then get EncryptedContentBytes
		EncryptedContent, err := userdata.UnmarshalThenValidateHMACWrapperAndGetCiphertext(HMACWrapperOfCurContentBytes, FileMACKey)
		if err != nil {
			return nil, errors.New("6-2. Failed to UnmarshalThenValidateHMACWrapperAndGetCiphertext in while loop in LoadFile: " + err.Error())
		}
		// EncryptedContent Retrieved

		// 6-3. Decrypt to get CurContent (No need to Unmarshal since content is []byte already)
		CurContent := userlib.SymDec(FileDECKey, EncryptedContent)
		// CurContent Retrieved

		// 6-3.5. Encrypt again with different UUID
		err = userdata.EncryptWithDifferentIV(FileDECKey, CurContent, CurLinkedListBlock.ContentUUID, FileMACKey) //come back to fix
		if err != nil {
			return nil, errors.New("6-3.5. Failed to EncryptWithDifferentIV in while loop in LoadFile: " + err.Error())
		}

		// 6-4. Append CurContent to content
		content = append(content, CurContent...)
	}

	/*storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)*/
	return content, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	// Make IndicatorStruct for that child with the same fileKey you have and return UUID of HMACWrapOfInvitationStruct
	// InvitationStruct will be encrypted with child's public key

	/*
		// 0. Get FileStruct
		CurFileStruct, FileMACKey, FileDECKey, FileStructUUID, err := userdata.GetFileStruct(filename)
		if err != nil {
			return nil, err
		}
		// FileStruct Retrieved
	*/

	// 1. Initialize InvitationStruct
	var UserInvitationStruct InvitationStruct
	var HybridStructForChild HybridStruct

	// 2. Get the key of child's public key
	ChildPublicENCKey, err := GetUserPublicENCKey(recipientUsername)
	if err != nil {
		return uuid.Nil, errors.New("an error occurred while getting UserPublicENCKey: " + err.Error())
	}
	UserInvitationStruct.Childname = recipientUsername
	// child's PublicENCKey Setings Finished

	// 4. I guess we need to get NameSpaceStruct to get FileInfo of it and special MACKey and DECKey for it
	UserNameSpacePtr, err := userdata.GetNameSpaceStruct()
	if err != nil {
		return uuid.Nil, errors.New("an error occurred while getting NameSpaceStruct in inv: " + err.Error())
	}
	// NameSpaceStruct Retrieved

	// 5. Get FileInfo of filename
	CurFileInfo := UserNameSpacePtr.NameSpace[filename].Dict[userdata.Username]
	// FileInfo Retrieved

	// 6. Get the HMACWrapperBytesOfUserIndicatorStruct
	HMACWrapperBytesOfUserIndicatorStruct, ok := userlib.DatastoreGet(CurFileInfo.IndicatorStructUUID)
	if !ok {
		return uuid.Nil, errors.New("An error occurred while retrieving the HMACWrapperBytes of original UserIndicatorStruct" + err.Error())
	}
	// HMACWrapperBytesOfUserIndicatorStruct Retrieved

	// 7. Get the EncryptedUserIndicatorStructBytes
	EncryptedUserIndicatorStructBytes, err := userdata.UnmarshalThenValidateHMACWrapperAndGetCiphertext(HMACWrapperBytesOfUserIndicatorStruct, CurFileInfo.IndicatorStructMACKey)
	if err != nil {
		return uuid.Nil, errors.New("an error occurred while getting unmarshaling and validating in inv: " + err.Error())
	}
	// Encrypted Bytes of User IndicatorStruct Retrieved

	// 8. Decrypt then Unmarshal to get UserIndicatorStruct
	UserIndicatorStruct, err := userdata.DecryptThenUnmarshalIndicatorStruct(EncryptedUserIndicatorStructBytes, CurFileInfo.IndicatorStructDECKey, CurFileInfo.IndicatorStructUUID, CurFileInfo.IndicatorStructMACKey)
	if err != nil {
		return uuid.Nil, errors.New("an error occurred while getting decrypting and unmarshalling in inv: " + err.Error())
	}
	// User IndicatorStruct Loading Succeeded

	// 9. Make a duplicate IndicatorStruct out of User IndicatorStruct
	ParentIndicatorStruct := IndicatorStructMaker(UserIndicatorStruct.FileOrNextIndicatorStructMACKey, UserIndicatorStruct.FileOrNextIndicatorStructDECKey, UserIndicatorStruct.FileOrNextIndicatorStructUUID, UserIndicatorStruct.LastPtr)
	// ParentIndicatorStruct Finished

	// 10. Marshal then Encrypt to get EncryptedParentIndicatorStructBytes
	EncryptedParentIndicatorStructBytes, ParentIndicatorStructMACKey, ParentIndicatorStructDECKey, err := userdata.MarshalThenEncryptIndicatorStruct(ParentIndicatorStruct)
	if len(ParentIndicatorStructMACKey) != 16 {
		return uuid.Nil, errors.New("ParentIndicatorStructMACKey is not 16 bytes")
	}
	if len(ParentIndicatorStructDECKey) != 16 {
		return uuid.Nil, errors.New("ParentIndicatorStructDECKey is not 16 bytes")
	}
	if err != nil {
		return uuid.Nil, errors.New("an error occurred while getting EncParentIndicatorStructBytes in inv: " + err.Error())
	}
	// Encrypted ParentIndicatorStruct Bytes Settings Finished

	// 11. Get UUID of ParentIndicatorStruct before CipherWrap the ParentIndicatorStruct
	// First I tried deterministic UUID with Child's name + UserSecretSalt + filename, but then Mallory would attempt Brute Force UUID to obtain Parent's SecretSalt
	// So I went back to a random UUID for IndicatorStruct being shared
	ParentIndicatorStructUUID := uuid.New()
	// UUID for FileInfo inside Parent's NameSpace Retrieved

	// 12. CipherWrap the ParentIndicatorStruct at that UUID
	err = userdata.CipherWrap(EncryptedParentIndicatorStructBytes, ParentIndicatorStructMACKey, ParentIndicatorStructUUID)
	if err != nil {
		return uuid.Nil, errors.New("an error occurred while cipherwrapping parentindicatorstruct in inv: " + err.Error())
	}
	// DatastoreSet of HMACWrapper of ParentIndicator Finished

	// 13. Construct a new FileInfo at Parent's NameSpaceStruct
	var ParentFileInfo FileInfo
	ParentFileInfo.IndicatorStructUUID = ParentIndicatorStructUUID
	ParentFileInfo.IndicatorStructMACKey = ParentIndicatorStructMACKey
	ParentFileInfo.IndicatorStructDECKey = ParentIndicatorStructDECKey

	// 14. Set up FileInfo to InvitationStruct
	UserInvitationStruct.ParentIndicatorStructUUID = ParentFileInfo.IndicatorStructUUID
	UserInvitationStruct.ParentIndicatorStructMACKey = ParentFileInfo.IndicatorStructMACKey
	UserInvitationStruct.ParentIndicatorStructDECKey = ParentFileInfo.IndicatorStructDECKey
	// Settings Finished

	// 17. Make a Child MACKey for this file
	ChildKeySalt := userlib.RandomBytes(16)
	ChildMACKey, err := userlib.HashKDF(ChildKeySalt, []byte("file-mac-key"))
	if err != nil {
		return uuid.Nil, err
	}
	ChildMACKey = ChildMACKey[:16]
	// ChildMACKey Finished

	// 18. Make a Child DECKey for this file
	ChildDECKey, err := userlib.HashKDF(ChildMACKey, []byte("file-dec-key"))
	if err != nil {
		return uuid.Nil, err
	}
	ChildDECKey = ChildDECKey[:16]
	// ChildDECKey Finished

	// 19. Make a InvitationDECKey
	InvitationStructDECKey, err := userlib.HashKDF(ChildDECKey, []byte("invitation-struct-dec-key"))
	if err != nil {
		return uuid.Nil, err
	}
	InvitationStructDECKey = InvitationStructDECKey[:16]
	// ChildDECKey Finished

	HybridStructForChild.InvitationStructDECKey = InvitationStructDECKey
	HybridStructForChild.InvitationStructUUID = uuid.New()
	//InvitationStructUUID is UUID where HMACWrapperBytes of InvitationStruct will be stored
	UserInvitationStruct.ChildUUID = uuid.New()
	//ChildUUID is UUID where ChildIndicatorStruct in Child's FileInfo in NameSpace will be stored
	invitationPtr = uuid.New()
	//invitationPtr is UUID where HMACWrapperBytes of HybridStruct pointing to HMACWrapperBytes of User InvitationStruct

	UserInvitationStruct.ChildMACKey = ChildMACKey
	UserInvitationStruct.ChildDECKey = ChildDECKey

	ParentFileInfo.HasChild = true
	ParentFileInfo.ChildIndicatorStructUUID = UserInvitationStruct.ChildUUID
	ParentFileInfo.ChildIndicatorStructMACKey = UserInvitationStruct.ChildMACKey
	ParentFileInfo.ChildIndicatorStructDECKey = UserInvitationStruct.ChildDECKey
	// InvitationStruct Settings Finished

	// 17. Marshal then Encrypt InvitationStruct with Hybrid.InvitationStructDECKey to get EncryptedUserInvitationStructBytes
	EncryptedUserInvitationStructBytes, err := userdata.MarshalThenEncryptInvitationStruct(UserInvitationStruct, HybridStructForChild.InvitationStructDECKey)
	if err != nil {
		return uuid.Nil, errors.New("an error occurred while getting ciphertext of EncInvStruc in inv: " + err.Error())
	}
	// Ciphertext Finished

	// 18. Manual CipherWrap EncryptedUserInvitationStructBytes at Hybrid.InvitationStructUUID
	var SigWrapperOfInvitationStruct HMACWrapper
	SigWrapperOfInvitationStruct.Ciphertext = EncryptedUserInvitationStructBytes
	SigOfEncryptedUserInvitationStructBytes, err := userlib.DSSign(userdata.UserSignKey, SigWrapperOfInvitationStruct.Ciphertext)
	if err != nil {
		return uuid.Nil, errors.New("An error occurred while signing EncryptedBytes of UserInvitationStruct" + err.Error())
	}
	SigWrapperOfInvitationStruct.MAC = SigOfEncryptedUserInvitationStructBytes
	// SigWrap of InvitationStruct Complete

	// 19. Marshal to get SigWrapperBytes to Store the SigWrapperBytes
	SigWrapperBytesOfInvitationStruct, err := json.Marshal(SigWrapperOfInvitationStruct)
	if err != nil {
		return uuid.Nil, errors.New("An error occurred while Marshaling SigWrapperOfInvitationStruct: " + err.Error())
	}
	// Marshal Complete

	// 20. Store SigWrapperBytes at InvitationStructUUID
	userlib.DatastoreSet(HybridStructForChild.InvitationStructUUID, SigWrapperBytesOfInvitationStruct)
	// SigWrapperBytes of InvitationStruct Stored

	// 21. Marshal then Encrypt HybridStructForChild with Child's public key
	EncryptedHybridStructForChildBytes, err := userdata.MarshalThenEncryptHybridStruct(HybridStructForChild, ChildPublicENCKey)
	if err != nil {
		return uuid.Nil, errors.New("An error occurred while marshal then encrypt HybridStruct with Child's public key: " + err.Error())
	}
	//EncryptedBytes Retrieved

	// 22. Make SigWrapper
	var SigWrapperOfHybridStructForChild HMACWrapper
	SigWrapperOfHybridStructForChild.Ciphertext = EncryptedHybridStructForChildBytes
	SigOfEncryptedHybridStructForChildBytes, err := userlib.DSSign(userdata.UserSignKey, SigWrapperOfHybridStructForChild.Ciphertext)
	if err != nil {
		return uuid.Nil, errors.New("An error occurred while signing EncryptedBytes of HybridStruct for Child" + err.Error())
	}
	SigWrapperOfHybridStructForChild.MAC = SigOfEncryptedHybridStructForChildBytes
	// SigWrap of HybridStruct Complete

	// 23. Marshal it
	SigWrapperBytesOfHybridStructForChild, err := json.Marshal(SigWrapperOfHybridStructForChild)
	if err != nil {
		return uuid.Nil, errors.New("An error occurred while Marshaling SigWrapperOfHybridStructForChild: " + err.Error())
	}
	// Marshal Complete

	// 24. Store SigWrapperBytesOfHybridStructForChild at invitationPtr
	userlib.DatastoreSet(invitationPtr, SigWrapperBytesOfHybridStructForChild)
	// SigWrapperBytesOfHybridStructForChild Stored

	// 19. Setup Parent's Namespace
	UserNameSpacePtr.NameSpace[filename].Dict[recipientUsername] = ParentFileInfo

	// 20. Update Parent's NameSpace
	err = userdata.CipherUpdateNameSpaceStruct(*UserNameSpacePtr)
	if err != nil {
		return uuid.Nil, errors.New("an error occurred while updating CipherUpdateNameSpaceStruct in inv: " + err.Error())
	}

	return invitationPtr, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// 0. Get the Child's NameSpace to check the filenames
	ChildNameSpaceStructPtr, err := userdata.GetNameSpaceStruct()
	if err != nil {
		return errors.New("An error occurred while getting NameSpaceStruct in AcceptInvitation: " + err.Error())
	}
	exist := ChildNameSpaceStructPtr.FilenameChecker(filename, userdata.Username)
	if exist {
		return errors.New("This filename already exists in your NameSpace")
	}
	// Filename Validated

	// 1. Get the SigWrapper of Hybrid
	SigWrapperBytesOfHybrid, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("An error occurred while retrieving SigWrapperBytesOfHybrid")
	}
	// SigWrapperBytes Retrieved

	// 2. Unmarshal to get SigWrapperOfHybrid
	var SigWrapperOfHybrid HMACWrapper
	err = json.Unmarshal(SigWrapperBytesOfHybrid, &SigWrapperOfHybrid)
	if err != nil {
		return errors.New("An error occurred while unmarshal SigWrapperBytes of HybridStruct: " + err.Error())
	}
	// SigWrapperOfHybrid Retrieved

	// 3. Go get Parent's Sign
	AliceSignVerificationKey, err := GetUserSignVerificationKey(senderUsername)
	if err != nil {
		return errors.New("An error occurred while getting Parent's Sign Verification Key: " + err.Error())
	}
	// Parent's Sign Retrieved

	// 4. Verify MAC = sig = Signed Ciphertext
	err = userlib.DSVerify(AliceSignVerificationKey, SigWrapperOfHybrid.Ciphertext, SigWrapperOfHybrid.MAC)
	if err != nil {
		return errors.New("This Encrypted Ciphertext of Hybrid is potentially corrypted: " + err.Error())
	}
	// Hybrid Struct Integrity Secured

	// 5. Decrypt then Unmarshal to get Hybrid
	ChildHybridStruct, err := userdata.DecryptThenUnmarshalHybridStruct(SigWrapperOfHybrid.Ciphertext)
	if err != nil {
		return errors.New("An error occurred while decrypt then unmarshal HybridStruct: " + err.Error())
	}
	// HybridStructForChild Retrieved

	// 6. With InvitationStruct info inside ChildHybridStruct, get the SigWrapperBytes of EncryptedInvitationStructBytesSignedByParent
	SigWrapperBytesOfEncryptedInvitationStructBytes, ok := userlib.DatastoreGet(ChildHybridStruct.InvitationStructUUID)
	if !ok {
		return errors.New("An error occurred while retrieving SigWrapper of EncryptedInvitationStructBytes")
	}
	// Ciphertext of InvitationStruct Retrieved

	// 7. Unmarshal to get SigWrapper
	var SigWrapperOfEncryptedInvitationStructBytes HMACWrapper
	err = json.Unmarshal(SigWrapperBytesOfEncryptedInvitationStructBytes, &SigWrapperOfEncryptedInvitationStructBytes)
	if err != nil {
		return errors.New("An error occurred while decrypt then unmarshal SigWrapper Of Encrypted InvitationStruct Bytes: " + err.Error())
	}
	// For this time, HMACWrapper will have sig instead of MAC inside.
	// MAC: sig, signed Ciphertext
	// Ciphertext: EncryptedInvitationStructBytes

	// 8. Validate Parent's Sign on EncryptedInvitationStruct
	err = userlib.DSVerify(AliceSignVerificationKey, SigWrapperOfEncryptedInvitationStructBytes.Ciphertext, SigWrapperOfEncryptedInvitationStructBytes.MAC)
	if err != nil {
		return errors.New("An error occurred while verifying Parent's Sign in HMACWrapper of SigWrapperBytesOfEncryptedInvitationStructBytes: " + err.Error())
	}
	// It is signed by sender == Parent Alice!

	// 9. Decrypt Ciphertext with Hybrid's InvitationStructDECKey
	CurInvitationStruct, err := userdata.DecryptThenUnmarshalInvitationStruct(SigWrapperOfEncryptedInvitationStructBytes.Ciphertext, ChildHybridStruct.InvitationStructDECKey)
	if err != nil {
		return errors.New("An error occurred while Decrypt Then Unmarshal InvitationStruct of  SigWrapperBytesOfEncryptedInvitationStructBytes.Ciphertext: " + err.Error())
	}
	// InvitationStruct Retrieved

	// 10. Last check the name
	if CurInvitationStruct.Childname != userdata.Username {
		return errors.New("An error Occurred: InvitationStruct has different Childname than mine")
	}
	// InvitationStruct is indeed for me!

	// Start making IndicatorStruct out of InvitationStruct then store it inside my NameSpace with appropriate FileInfo
	// UUID must be the one provided by InvitationStruct
	// CurInvitationStruct.ChildIndicatorStructUUID

	// 11. Make a ChildIndicatorStruct
	ChildIndicatorStruct := IndicatorStructMaker(CurInvitationStruct.ParentIndicatorStructMACKey, CurInvitationStruct.ParentIndicatorStructDECKey, CurInvitationStruct.ParentIndicatorStructUUID, false)
	// ChildIndicatorStruct Settings Finished

	// 13. Make a FileInfo first
	var ChildFileInfo FileInfo
	ChildFileInfo.IndicatorStructUUID = CurInvitationStruct.ChildUUID
	ChildFileInfo.IndicatorStructDECKey = CurInvitationStruct.ChildDECKey
	ChildFileInfo.IndicatorStructMACKey = CurInvitationStruct.ChildMACKey
	// FileInfo Template Finished

	// 12. MarshalThenEncryptIndicatorStruct
	EncryptedChildIndicatorStructBytes, err := userdata.MarshalThenEncryptIndicatorStructWithKeys(ChildIndicatorStruct, ChildFileInfo.IndicatorStructDECKey)
	if err != nil {
		return err
	}
	// Marshal and Encryption to get EncryptedBytes of Child IndicatorStruct Finished

	// 14. CipherWrap EncryptedBytes of ChildIndicatorStruct to get and store HMACWrapperBytesOfChildIndicator
	err = userdata.CipherWrap(EncryptedChildIndicatorStructBytes, ChildFileInfo.IndicatorStructMACKey, ChildFileInfo.IndicatorStructUUID)
	if err != nil {
		return err
	}
	// ChildIndicator Settings Finished. Now Set up NameSpace

	// 15. Update User's NameSpace
	err = ChildNameSpaceStructPtr.NameSpaceFileSetter(filename, userdata.Username, ChildFileInfo)
	if err != nil {
		return err
	}
	err = userdata.CipherUpdateNameSpaceStruct(*ChildNameSpaceStructPtr)
	if err != nil {
		return err
	}
	// NameSpace Updated well
	ChildNameSpaceStructPtr, err = userdata.GetNameSpaceStruct()
	if err != nil {
		return errors.New("An error occurred while getting NameSpaceStruct in AcceptInvitation: " + err.Error())
	}
	exist = ChildNameSpaceStructPtr.FilenameChecker(filename, userdata.Username)
	if !exist {
		return errors.New("This filename fails to exists in child's NameSpace")
	}
	// Filename Validated

	HMACWrapperBytesOfIndicatorStruct, ok := userlib.DatastoreGet(ChildFileInfo.IndicatorStructUUID)
	if !ok {
		return errors.New("Failed to get HMACWrapperBytesOfIndicatorStruct")
	}
	EncryptedIndicatorStructBytes, err := userdata.UnmarshalThenValidateHMACWrapperAndGetCiphertext(HMACWrapperBytesOfIndicatorStruct, ChildFileInfo.IndicatorStructMACKey)
	if err != nil {
		return errors.New("Failed to get EncryptedChildIndicatorStructBytes: " + err.Error())
	}
	ChildIndicatorStruct, err = userdata.DecryptThenUnmarshalIndicatorStruct(EncryptedIndicatorStructBytes, ChildFileInfo.IndicatorStructDECKey, ChildFileInfo.IndicatorStructUUID, ChildFileInfo.IndicatorStructMACKey)
	if err != nil {
		return errors.New("Failed to get ChildIndicatorStruct: " + err.Error())
	}

	return nil
}
func (UserNameSpaceStruct *NameSpaceStruct) GetFileInfoDictPtr(filename string) (UserFileInfoDictPtr *FileInfoDict) {
	UserFileInfoDict := UserNameSpaceStruct.NameSpace[filename]
	UserFileInfoDictPtr = &UserFileInfoDict
	return UserFileInfoDictPtr
}
func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// 0. Check if there is this filename in NameSpace first
	UserNameSpacePtr, err := userdata.GetNameSpaceStruct()
	if err != nil {
		return err
	}
	exist := UserNameSpacePtr.FilenameChecker(filename, recipientUsername)
	if exist != true {
		return errors.New("File doesn't exist: " + err.Error())
	}
	// There exists this filename!

	// 1. Check if you are the file owner. Your IndicatorStruct should say LastPtr:true!
	OldUserFileInfoDict := UserNameSpacePtr.GetFileInfoDictPtr(filename)
	OldUserFileInfo := OldUserFileInfoDict.Dict[userdata.Username]
	// User FileInfo Retrieved

	// 2. Get HMACWrapperBytes of the IndicatorStruct Now
	HMACWrapperBytesOfIndicatorStruct, ok := userlib.DatastoreGet(OldUserFileInfo.IndicatorStructUUID)
	if !ok {
		return errors.New("HMACWrapperBytes of IndicatorStruct not existed: " + err.Error())
	}
	EncryptedOldUserIndicatorStructBytes, err := userdata.UnmarshalThenValidateHMACWrapperAndGetCiphertext(HMACWrapperBytesOfIndicatorStruct, OldUserFileInfo.IndicatorStructMACKey)
	if err != nil {
		return err
	}
	// Encrypted bytes of User IndicatorStruct Retrieved

	// 3. Decrypt then Unmarshal to get User IndicatorStruct
	OldUserIndicatorStruct, err := userdata.DecryptThenUnmarshalIndicatorStruct(EncryptedOldUserIndicatorStructBytes, OldUserFileInfo.IndicatorStructDECKey, OldUserFileInfo.IndicatorStructUUID, OldUserFileInfo.IndicatorStructMACKey)
	if err != nil {
		return err
	}
	// User IndicatorStruct Retrieved

	// 4. Check if LastPtr is true
	if OldUserIndicatorStruct.LastPtr != true {
		return errors.New("You are not the file owner: " + err.Error())
	}
	// You are the file owner!

	// 9. Get content
	content, err := userdata.LoadFile(filename)
	if err != nil {
		return errors.New("LoadFile Failed in Revoke: " + err.Error())
	}
	// 10. StoreContent
	OldUserNameSpace := UserNameSpacePtr.NameSpace[filename].Dict

	// 5. Remove recipientUsername FileInfo
	UserFileStruct, FileMACKey, FileDECKey, FileStructUUID, err := userdata.GetFileStruct(filename)
	if err != nil {
		return errors.New("Failed to get FileStruct: " + err.Error())
	}
	HMACWrapperBytesOfHeadLinkedListBlock, ok := userlib.DatastoreGet(UserFileStruct.HeadPtr)
	if !ok {
		return errors.New("Failed to get HMACWrapperBytesOfHeadLinkedListBlock... ")
	}
	EncryptedHeadLinkedListBlockBytes, err := userdata.UnmarshalThenValidateHMACWrapperAndGetCiphertext(HMACWrapperBytesOfHeadLinkedListBlock, FileMACKey)
	if err != nil {
		return errors.New("Failed to get EncryptedHeadLinkedListBlockBytes: " + err.Error())
	}
	UserLinkedListBlock, err := userdata.DecryptThenUnmarshalLinkedListBlock(EncryptedHeadLinkedListBlockBytes, FileDECKey, FileMACKey, UserFileStruct.HeadPtr)
	if err != nil {
		return errors.New("Failed to get UserLinkedListBlock: " + err.Error())
	}

	// TO WORK ON: HOW TO MARSHAL AND ENCRYPT? DOESN't WORK RIGHT NOW
	ChildFileInfo := UserNameSpacePtr.NameSpace[filename].Dict[recipientUsername]
	var NilHMACWrapperBytes HMACWrapper
	NilBytes, err := json.Marshal(NilHMACWrapperBytes)
	userlib.DatastoreSet(ChildFileInfo.IndicatorStructUUID, NilBytes)
	/*
		RecipientIndicatorStruct
		RecipientIndicatorStruct.ChildIndicatorStructDECKey = userlib.RandomBytes(16)
		RecipientIndicatorStruct.ChildIndicatorStructMACKey = userlib.RandomBytes(16)
		RecipientIndicatorStruct.ChildIndicatorStructUUID = UserNameSpacePtr.NameSpace[filename].Dict[recipientUsername].ChildIndicatorStructUUID
	*/
	// EncryptedRecipientIndicatorStructBytes, err := MarshalThenEncryptUserStruct()

	// UserNameSpacePtr.NameSpace[filename].Dict[recipientUsername] = RecipientIndicatorStruct

	userlib.DatastoreDelete(UserLinkedListBlock.ContentUUID)
	//UserLinkedListBlockUUID := UserFileStruct.HeadPtr
	for !UserLinkedListBlock.LastPtr {
		HMACWrapperBytesOfHeadLinkedListBlock, ok := userlib.DatastoreGet(UserLinkedListBlock.NextUUID)
		if !ok {
			return errors.New("Failed to get HMACWrapperBytesOfHeadLinkedListBlock... ")
		}
		//userlib.DatastoreDelete(UserLinkedListBlockUUID)
		EncryptedHeadLinkedListBlockBytes, err := userdata.UnmarshalThenValidateHMACWrapperAndGetCiphertext(HMACWrapperBytesOfHeadLinkedListBlock, FileMACKey)
		if err != nil {
			return errors.New("Failed to get EncryptedHeadLinkedListBlockBytes: " + err.Error())
		}
		UserLinkedListBlock, err := userdata.DecryptThenUnmarshalLinkedListBlock(EncryptedHeadLinkedListBlockBytes, FileDECKey, FileMACKey, UserFileStruct.HeadPtr)
		if err != nil {
			return errors.New("Failed to get UserLinkedListBlock: " + err.Error())
		}
		userlib.DatastoreDelete(UserLinkedListBlock.ContentUUID)
		//UserLinkedListBlockUUID = UserLinkedListBlock.NextUUID

	}
	//userlib.DatastoreDelete(UserFileStruct.TailPtr)
	userlib.DatastoreDelete(FileStructUUID)
	userlib.DatastoreDelete(OldUserFileInfo.IndicatorStructUUID)
	userlib.DatastoreDelete(UserNameSpacePtr.NameSpace[filename].Dict[recipientUsername].IndicatorStructUUID)

	delete(UserNameSpacePtr.NameSpace[filename].Dict, recipientUsername)
	delete(UserNameSpacePtr.NameSpace[filename].Dict, userdata.Username)

	err = userdata.CipherUpdateNameSpaceStruct(*UserNameSpacePtr)
	if err != nil {
		return errors.New("Revoke Cipher update fails" + err.Error())
	}

	// Delete Complete
	/*
		// Go to your parent parent IndicatorStruct, decrypt it,
		// 6. Get the HMACWrapperBytes of FileStruct. LastPtr is true so if you go up once, you are at FileStruct
		HMACWrapperBytesOfOldFileStruct, ok := userlib.DatastoreGet(OldUserIndicatorStruct.FileOrNextIndicatorStructUUID)
		if !ok {
			return errors.New("File doesn't exist: " + err.Error())
		}
		// HMACWrapperBytesOfFileStruct Retrieved

		// 7. Get EncryptedFileStructBytes by Validate
		EncryptedOldFileStructBytes, err := userdata.UnmarshalThenValidateHMACWrapperAndGetCiphertext(HMACWrapperBytesOfOldFileStruct, OldUserIndicatorStruct.FileOrNextIndicatorStructMACKey)
		if err != nil {
			return err
		}
		// Encrypted Bytes of FileStruct Retrieved

		// 8. Decrypt Then Unmarshal to get FileStruct
		OldFileStruct, err := userdata.DecryptThenUnmarshalFileStruct(EncryptedOldFileStructBytes, OldUserIndicatorStruct.FileOrNextIndicatorStructDECKey)
		if err != nil {
			return err
		}
		// OldFileStruct Retrieved
	*/

	err = userdata.StoreFile(filename, content)
	if err != nil {
		return errors.New("StoreFile Failed in Revoke: " + err.Error())
	}
	// I will assume that UserNameSpacePtr doesn't change and OldUserNameSpace has the old FileInfos

	for Childname, OldParentIndicatorStructFileInfo := range OldUserNameSpace {
		err = userdata.UpdateParentIndicatorStruct(filename, Childname, OldParentIndicatorStructFileInfo)
		if err != nil {
			return errors.New("UpdateParentIndicatorStruct: " + err.Error())
		}
	}

	return nil
}
func (userdata *User) UpdateParentIndicatorStruct(filename string, Childname string, OldParentFileInfo FileInfo) (err error) {
	// Given ParentFileInfo for ParentIndicatorStruct for each child, duplicate it and store it inside FileInfoDict.Dict[ChildName]
	// with different FileStructMACKey and FileStructDECKey for FileStruct
	// and fix Child IndicatorStruct as well with ChildMACKey and ChildDECKey you have on OldParentFileInfo

	// Get the UserIndicatorStruct
	// 1. Get NameSpaceStruct
	UserNameSpaceStructPtr, err := userdata.GetNameSpaceStruct()
	if err != nil {
		return errors.New("An error Occurred while getting User NameSpaceStruct Ptr" + err.Error())
	}
	// NameSpaceStruct Retrieved

	// 2. There is no way the childname is already in the Dictionary
	if UserNameSpaceStructPtr.FilenameChecker(filename, userdata.Username) {
		return errors.New("This can't be happening. I just start building up new FileInfoDict but there's a ChildName already")
	}
	// Error Checked

	// 3. Retrieve NewFileInfo for us to refer
	NewFileInfo := UserNameSpaceStructPtr.NameSpace[filename].Dict[userdata.Username]
	// NewFileInfo Retrieved

	// 4. We need Information inside NewUserIndicatorStruct. Get HMACWrapperBytes of NewUserIndicatorStruct
	HMACWrapperBytesOfNewUserIndicatorStruct, ok := userlib.DatastoreGet(NewFileInfo.IndicatorStructUUID)
	if !ok {
		return errors.New("An error occurred while getting HMACWrapper Bytes of New User IndicatorStruct" + err.Error())
	}
	// HMACWrapper Bytes Retrieved

	// 5. Get EncryptedNewUserIndicatorStructBytes
	EncryptedNewUserIndicatorStructBytes, err := userdata.UnmarshalThenValidateHMACWrapperAndGetCiphertext(HMACWrapperBytesOfNewUserIndicatorStruct, NewFileInfo.IndicatorStructMACKey)
	if err != nil {
		return errors.New("An error occurred while Unmarshal Then Validate Then Get Encrypted Bytes of New User IndicatorStruct" + err.Error())
	}

	// 6. Decrypt then Unmarshal to get New UserIndicatrewe
	NewUserIndicatorStruct, err := userdata.DecryptThenUnmarshalIndicatorStruct(EncryptedNewUserIndicatorStructBytes, NewFileInfo.IndicatorStructDECKey, NewFileInfo.IndicatorStructUUID, NewFileInfo.IndicatorStructMACKey)
	if err != nil {
		return errors.New("An error occurred while Decrypt then Unmarshal New User Indicator Struct" + err.Error())
	}

	// 7. Make a New Parent IndicatorStruct for this child refer to UserIndicatorStruct which is described as NewFileInfo
	NewParentIndicatorStruct := IndicatorStructMaker(NewUserIndicatorStruct.FileOrNextIndicatorStructMACKey, NewUserIndicatorStruct.FileOrNextIndicatorStructDECKey, NewUserIndicatorStruct.FileOrNextIndicatorStructUUID, true)
	// New Parent IndicatorStruct Complete

	/* These info is for NewParentIndicatorStruct MACKey and DECKey, you decrypt and validate it with these keys
	stays the same! for file accessing our ParentIndicatorStruct

	OldParentFileInfo.IndicatorStructMACKey
	OldParentFileInfo.IndicatorStructDECKey
	OldParentFileInfo.IndicatorStructUUID
	*/

	// 8. MarshalThenEncrypt to get EncryptedParentIndicatorStructBytes
	EncryptedParentIndicatorStructBytes, MACKeyForNewParentIndicatorStruct, DECKeyForNewParentIndicatorStruct, err := userdata.MarshalThenEncryptIndicatorStruct(NewParentIndicatorStruct)
	if len(MACKeyForNewParentIndicatorStruct) != 16 {
		return errors.New("MACKeyForNewParentIndicatorStruct is not 16 bytes")
	}
	if len(DECKeyForNewParentIndicatorStruct) != 16 {
		return errors.New("DECKeyForNewParentIndicatorStruct is not 16 bytes")
	}
	if err != nil {
		return errors.New("An error occurred while Marshal then Encrypt New Parent IndicatorStruct with new keys" + err.Error())
	}
	// Encrypted Bytes of Parent IndicatorStruct Settings Finished

	// 9. CipherWrap at somewhere random
	UUIDForNewParentIndicatorStruct, err := userdata.CipherWrapAtSomewhereRandom(EncryptedParentIndicatorStructBytes, MACKeyForNewParentIndicatorStruct)
	if err != nil {
		return errors.New("An error occurred while Cipher wrapping EncryptedParentIndicatorStructBytes at somewhere random" + err.Error())
	}

	// 10. Make a FileInfo for it
	var NewParentFileInfo FileInfo
	NewParentFileInfo.IndicatorStructDECKey = DECKeyForNewParentIndicatorStruct
	NewParentFileInfo.IndicatorStructMACKey = MACKeyForNewParentIndicatorStruct
	NewParentFileInfo.IndicatorStructUUID = UUIDForNewParentIndicatorStruct
	NewParentFileInfo.HasChild = true
	// New Parent FileInfo settings finished
	/*
		// 11. Can we get ChildIndicatorStruct? Does our old info still works?
		HMACWrapperBytesOfChildIndicatorStruct, ok := userlib.DatastoreGet(OldParentFileInfo.ChildIndicatorStructUUID)
		if !ok {
			return errors.New("An error occurred while getting Child Indicator according to Old ParentFileInfo inside revoke" + err.Error())
		}
		EncryptedChildIndicatorStructBytes, err := userdata.UnmarshalThenValidateHMACWrapperAndGetCiphertext(HMACWrapperBytesOfChildIndicatorStruct, OldParentFileInfo.ChildIndicatorStructMACKey)
		if err != nil {
			return errors.New("I guess our old info about child Indicator MAC Doesn't work" + err.Error())
		}
		ChildIndicatorStruct, err := userdata.DecryptThenUnmarshalIndicatorStruct(EncryptedChildIndicatorStructBytes, OldParentFileInfo.ChildIndicatorStructDECKey)
		if err != nil {
			return errors.New("I guess our old info about child Indicator DEC Doesn't work" + err.Error())
		}
		// We got the Child IndicatorStruct

		// 12. Finish NewParentFileInfo settings
	*/
	NewParentFileInfo.ChildIndicatorStructDECKey = OldParentFileInfo.ChildIndicatorStructDECKey
	NewParentFileInfo.ChildIndicatorStructMACKey = OldParentFileInfo.ChildIndicatorStructMACKey
	NewParentFileInfo.ChildIndicatorStructUUID = OldParentFileInfo.ChildIndicatorStructUUID

	UserNameSpaceStructPtr.NameSpace[filename].Dict[Childname] = NewParentFileInfo

	// 13. Just make a new ChildIndicator for your child
	var ChildIndicatorStruct IndicatorStruct
	ChildIndicatorStruct.FileOrNextIndicatorStructMACKey = MACKeyForNewParentIndicatorStruct
	ChildIndicatorStruct.FileOrNextIndicatorStructDECKey = DECKeyForNewParentIndicatorStruct
	ChildIndicatorStruct.FileOrNextIndicatorStructUUID = UUIDForNewParentIndicatorStruct

	EncryptedChildIndicatorStructBytes, err := userdata.MarshalThenEncryptIndicatorStructWithKeys(ChildIndicatorStruct, NewParentFileInfo.ChildIndicatorStructDECKey)
	if err != nil {
		return errors.New("An error occurred while Marshal then Encrypt ChildIndicator Struct" + err.Error())
	}

	// 14. CipherWrap
	err = userdata.CipherWrap(EncryptedChildIndicatorStructBytes, NewParentFileInfo.ChildIndicatorStructMACKey, NewParentFileInfo.ChildIndicatorStructUUID)
	if err != nil {
		return errors.New("An error occurred while Cipherwrapping EncryptedBytes of ChildIndicatorStruct" + err.Error())
	}

	err = userdata.CipherUpdateNameSpaceStruct(*UserNameSpaceStructPtr)
	if err != nil {
		return errors.New("Cipher Update Failed" + err.Error())
	}

	return nil
}
