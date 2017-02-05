package main

import (
	"fmt"
	"crypto/rsa"
	"github.com/Cryptography/crypt"
	"github.com/Cryptography/ecdsasignverify"
	"crypto/sha256"
	"os"
)

var (
	publicKey  rsa.PublicKey
	privateKey *rsa.PrivateKey
)

func main() {

	privateKey = crypt.GetPrivateKey()
	publicKey  = crypt.GetPublicKeyFromPrivateKey(privateKey)
	fmt.Println("Private Key :" , privateKey)
	fmt.Println("Public Key  :" , publicKey)

	crypt.SaveByKey("private.key", privateKey)
	crypt.SaveByPEMKey("private.pem", privateKey)

	crypt.SaveByKey("public.key", publicKey)
	crypt.SaveByPublicPEMKey("public.pem", publicKey)

	hashed := []byte("This message is for Bob...!!!" +
		"         Regards" +
		"          Alice")

	hash := sha256.Sum256(hashed)
	 s, err := ecdsasignverify.Sign(hash, privateKey)
	fmt.Printf("Signature: %x\n", s, err)

	msg    := []byte("This message is for Bob...!!!" +
		"         Regards" +
		"          Alice")


	errv := ecdsasignverify.Verify(publicKey, msg, s)
	if errv != nil {
		fmt.Fprintln(os.Stderr, "\nError from verification: %s\n", errv)

	}else {
		fmt.Fprintf(os.Stderr, "\nError from verification: %s\n", errv)
	}


}

