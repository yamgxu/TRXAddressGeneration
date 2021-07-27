package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	secp256k1 "github.com/ipsn/go-secp256k1"
	"golang.org/x/crypto/sha3"
	"math/big"
)

const PrivateKeyBytes = 32

var base58Alphabets = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

func main() {

	key, err := GenerateKey()
	//key, err := hex.DecodeString("3707d39311de4b20605aeecd737591a9e734dd1355e25e54324749b00a6968c8")
	if err != nil {
		fmt.Errorf("err", err)
	}
	fmt.Printf("私钥:%x\n", key)
	public := ToPublic(key)
	fmt.Printf("公钥:%x\n", public)
	address := newAddress(public)
	fmt.Printf("地址:%s\n", address)

}

func GenerateKey() ([]byte, error) {
	key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	privkey := make([]byte, PrivateKeyBytes)
	blob := key.D.Bytes()
	copy(privkey[PrivateKeyBytes-len(blob):], blob)
	return privkey, nil
}
func ToPublic(pk []byte) []byte {
	x, y := secp256k1.S256().ScalarBaseMult(pk)
	return elliptic.Marshal(secp256k1.S256(), x, y)[1:]
}
func newAddress(pubkey []byte) string {
	payload := sha3.NewLegacyKeccak256()
	payload.Write(pubkey)
	sum := payload.Sum(nil)

	toString := "41" + hex.EncodeToString(sum[len(sum)-20:])
	address, _ := FromHexAddress(toString)
	return address
}

func FromHexAddress(hexAddress string) (string, error) {
	addrByte, err := hex.DecodeString(hexAddress)
	if err != nil {
		return "", err
	}

	sha := sha256.New()
	sha.Write(addrByte)
	shaStr := sha.Sum(nil)

	sha2 := sha256.New()
	sha2.Write(shaStr)
	shaStr2 := sha2.Sum(nil)

	addrByte = append(addrByte, shaStr2[:4]...)

	return string(base58Encode(addrByte)), nil
}

// base58Encode 编码
func base58Encode(input []byte) []byte {
	x := big.NewInt(0).SetBytes(input)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := &big.Int{}
	var result []byte
	for x.Cmp(zero) != 0 {
		x.DivMod(x, base, mod)
		result = append(result, base58Alphabets[mod.Int64()])
	}
	reverseBytes(result)
	return result
}
func base58Decode(input []byte) []byte {
	result := big.NewInt(0)
	for _, b := range input {
		charIndex := bytes.IndexByte(base58Alphabets, b)
		result.Mul(result, big.NewInt(58))
		result.Add(result, big.NewInt(int64(charIndex)))
	}
	decoded := result.Bytes()
	if input[0] == base58Alphabets[0] {
		decoded = append([]byte{0x00}, decoded...)
	}
	return decoded[:len(decoded)-4]
}

// reverseBytes 翻转字节
func reverseBytes(data []byte) {
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
}
