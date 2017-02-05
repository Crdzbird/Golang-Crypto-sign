package ecdsasignverify

import (
	"crypto/rsa"
	"crypto/rand"
	"crypto"
	"fmt"
	"os"
	"crypto/sha256"
)


func Sign(hash [32]byte, privateKey *rsa.PrivateKey) (s []byte, err error) {

	s, err = rsa.SignPKCS1v15(rand.Reader, privateKey,crypto.SHA256, hash[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
		return
	}
	return  s, nil
}

func Verify(publicKey rsa.PublicKey, msg, s []byte) (err error) {

	hashv := sha256.Sum256(msg)
	return rsa.VerifyPKCS1v15(&publicKey, crypto.SHA256, hashv[:], s)
}
