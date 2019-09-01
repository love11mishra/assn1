package assn1

import (
	"fmt" //1
	"reflect"
	"testing"

	"github.com/sarkarbidya/CS628-assn1/userlib"
)

// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInitUser(t *testing.T) {
	t.Log("Initialization test")
	userlib.DebugPrint = true
	userlib.DebugPrint = false
	_, err1 := InitUser("", "")
	if err1 != nil {
		t.Log("Failed to initialize user")

	} else {
		t.Error("Initialized invalid user", err1)
	}

	// add more test cases here
}

func TestUserStorage(t *testing.T) {
	InitUser("lavlesh", "mishra")
	u1, err1 := GetUser("lavlesh", "mishra")
	if err1 == nil && u1.Username == "lavlesh" {
		fmt.Printf("User name is %s", u1.Username)
		//t.Log("Cannot load data for invalid user", u1)
	} else {
		t.Error("Data loaded for invalid user", err1)
	}

	//add more test cases here
}

func TestFileStoreLoadAppend(t *testing.T) {
	data1 := userlib.RandomBytes(4096)
	u1, err := InitUser("lavlesh", "mishra")
	if err != nil {
		fmt.Printf("Problem in initialization")
	}
	u1, _ = GetUser("lavlesh", "mishra")

	err11 := u1.StoreFile("file1", data1)
	if err11 != nil {
		fmt.Printf("%v", err11)
		//return nil, err
	}
	data2, err := u1.LoadFile("file1", 0)
	if err != nil {
		fmt.Printf("%v", err)
		//return nil, err
	}
	if !reflect.DeepEqual(data1, data2) {
		t.Error("data corrupted")
	} else {
		t.Log("data is not corrupted")
	}
	//u3, _ := GetUser("lavlesh", "mishra")
	metadata := u1.Myfiles["file1"]
	fmt.Printf("file size before append: %v ", metadata.size)

	//testing fakefile
	err1 := u1.AppendFile("file1", data1)
	if err1 != nil {
		fmt.Printf("append error %v\n", err1)
		//t.Error("append fail")
	}
	//u2, _ := GetUser("lavlesh", "mishra")
	metadata1 := u1.Myfiles["file1"]
	fmt.Printf("file size after append: %v", metadata1.size)
	// add test cases here
}

func TestFileShareReceive(t *testing.T) {
	data1 := userlib.RandomBytes(4096)
	InitUser("lavlesh", "mishra")
	u1, _ := GetUser("lavlesh", "mishra")
	_ = u1.StoreFile("file1", data1)

	//data2 := userlib.RandomBytes(4096)
	InitUser("shashi", "bhushan")
	u2, _ := GetUser("shashi", "bhushan")
	//_ = u1.StoreFile("file2", data2)
	// add test cases here
	msgid, err := u1.ShareFile("file1", "shashi")
	if err != nil {
		fmt.Printf("error in sharefile is: %v", err)
	}
	err2 := u2.ReceiveFile("file3", "lavlesh", msgid)
	if err2 != nil {
		fmt.Printf("Error in receive file: %v\n ", err2)
	}
	//u2, _ = GetUser("shashi", "bhushan") //
	data3, err := u1.LoadFile("file1", 0)
	if err != nil {
		fmt.Printf("in u1 load %v", err)
		//return nil, err
	}
	if !reflect.DeepEqual(data3, data1) {
		t.Error("problem in store file")
	}
	data4, err1 := u2.LoadFile("file3", 0)
	if err1 != nil {
		fmt.Printf("in u2 load %v", err1)
		//return nil, err
	}

	if !reflect.DeepEqual(data3, data4) {
		t.Error("data corrupted")
	} else {
		t.Log("shared successfully")
	}

}
