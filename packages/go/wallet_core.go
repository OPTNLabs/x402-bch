package x402bch

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"fmt"
	"math/big"
	"strings"
)

//go:embed spec/conformance/v1/bip39-english.txt
var bip39EnglishWordList string

func validateBip39Mnemonic(mnemonic string) error {
	words := strings.Fields(mnemonic)
	if len(words) != 12 && len(words) != 15 && len(words) != 18 && len(words) != 21 && len(words) != 24 {
		return fmt.Errorf("invalid BIP39 English mnemonic")
	}
	list := strings.Split(strings.TrimSpace(bip39EnglishWordList), "\n")
	indices := make(map[string]int, len(list))
	for i, word := range list {
		indices[word] = i
	}
	bits := ""
	for _, word := range words {
		index, ok := indices[word]
		if !ok {
			return fmt.Errorf("invalid BIP39 English mnemonic")
		}
		bits += fmt.Sprintf("%011b", index)
	}
	entropyBits := len(words) * 11 * 32 / 33
	entropy, ok := new(big.Int).SetString(bits[:entropyBits], 2)
	if !ok || entropy == nil {
		return fmt.Errorf("invalid BIP39 entropy")
	}
	entropyBytes := leftPad32(entropy.Bytes())
	checksum := bits[entropyBits:]
	digest := sha256.Sum256(entropyBytes[32-(entropyBits/8):])
	expected := fmt.Sprintf("%08b", digest[0])[:len(checksum)]
	if checksum != expected {
		return fmt.Errorf("invalid BIP39 mnemonic checksum")
	}
	return nil
}

// BchTransactionRequest is the wallet-owned request derived from x402 requirements.
// The wallet remains responsible for UTXO selection, change, fees, and signing.
type BchTransactionRequest struct {
	Network     string
	PayTo       string
	Value       string
	Asset       string
	TokenAmount string
	TokenNFT    *NftState
	RequestHash string
}

type BchWalletAddress struct {
	Address   string
	Path      string
	Change    uint32
	Index     uint32
	PublicKey []byte
}

type BchDiscoveredAddress struct {
	Wallet BchWalletAddress
	Utxos  []BchUtxo
}

func DiscoverBchHdWalletAddresses(mnemonic, network string, provider BchProvider, gapLimit, maxAddresses, account uint32, passphrase string) ([]BchDiscoveredAddress, error) {
	if gapLimit == 0 || maxAddresses < gapLimit {
		return nil, fmt.Errorf("invalid HD discovery limits")
	}
	var result []BchDiscoveredAddress
	coin := uint32(1)
	if network == "bch:bitcoincash" {
		coin = 145
	}
	for _, change := range []uint32{0, 1} {
		var unused uint32
		for index := uint32(0); index < maxAddresses && unused < gapLimit; index++ {
			wallet, err := DeriveBchWalletAddress(mnemonic, network, change, index, account, passphrase, &coin)
			if err != nil {
				return nil, err
			}
			utxos, err := provider.ListUtxos(wallet.Address)
			if err != nil {
				return nil, err
			}
			result = append(result, BchDiscoveredAddress{Wallet: wallet, Utxos: utxos})
			if len(utxos) == 0 {
				unused++
			} else {
				unused = 0
			}
		}
	}
	return result, nil
}

type Secp256k1BchSigner struct {
	privateKey     []byte
	defaultNetwork string
}

func NewSecp256k1BchSignerFromMnemonic(mnemonic, network, passphrase string, change, index, account uint32) (*Secp256k1BchSigner, error) {
	if err := validateBip39Mnemonic(mnemonic); err != nil {
		return nil, err
	}
	key := deriveBip44PrivateKey(mnemonic, network, passphrase, change, index, account)
	return &Secp256k1BchSigner{privateKey: key, defaultNetwork: network}, nil
}
func (s *Secp256k1BchSigner) PublicKey() []byte {
	point := secpPointMul(new(big.Int).SetBytes(s.privateKey), secp256k1G)
	return append([]byte{byte(2 | point.y.Bit(0))}, leftPad32(point.x.Bytes())...)
}
func (s *Secp256k1BchSigner) Address(network string) (string, error) {
	if network == "mainnet" {
		network = "bch:bitcoincash"
	}
	if network == "chipnet" {
		network = "bch:bchtest"
	}
	script := append([]byte{0x76, 0xa9, 0x14}, hash160(s.PublicKey())...)
	script = append(script, 0x88, 0xac)
	address, err := EncodeCashAddress(script, network, false)
	return address, err
}
func (s *Secp256k1BchSigner) SignDigest(digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("BCH signing digest must be 32 bytes")
	}
	v, k := bytes.Repeat([]byte{1}, 32), make([]byte, 32)
	x := s.privateKey
	mac := hmac.New(sha256.New, k)
	mac.Write(append(append(append([]byte{}, v...), 0), append(x, digest...)...))
	k = mac.Sum(nil)
	mac = hmac.New(sha256.New, k)
	mac.Write(v)
	v = mac.Sum(nil)
	mac = hmac.New(sha256.New, k)
	mac.Write(append(append(append([]byte{}, v...), 1), append(x, digest...)...))
	k = mac.Sum(nil)
	mac = hmac.New(sha256.New, k)
	mac.Write(v)
	v = mac.Sum(nil)
	for {
		mac = hmac.New(sha256.New, k)
		mac.Write(v)
		v = mac.Sum(nil)
		nonce := new(big.Int).SetBytes(v)
		if nonce.Sign() > 0 && nonce.Cmp(secp256k1N) < 0 {
			point := secpPointMul(nonce, secp256k1G)
			r := new(big.Int).Mod(point.x, secp256k1N)
			if r.Sign() != 0 {
				z := new(big.Int).SetBytes(digest)
				sValue := new(big.Int).Mul(new(big.Int).ModInverse(nonce, secp256k1N), new(big.Int).Add(z, new(big.Int).Mul(r, new(big.Int).SetBytes(x))))
				sValue.Mod(sValue, secp256k1N)
				if sValue.Cmp(new(big.Int).Rsh(new(big.Int).Set(secp256k1N), 1)) > 0 {
					sValue.Sub(secp256k1N, sValue)
				}
				return encodeDerSignature(r, sValue), nil
			}
		}
		mac = hmac.New(sha256.New, k)
		mac.Write(append(v, 0))
		k = mac.Sum(nil)
		mac = hmac.New(sha256.New, k)
		mac.Write(v)
		v = mac.Sum(nil)
	}
}
func encodeDerSignature(r, s *big.Int) []byte {
	integer := func(value *big.Int) []byte {
		raw := value.Bytes()
		if len(raw) == 0 {
			raw = []byte{0}
		}
		if raw[0]&0x80 != 0 {
			raw = append([]byte{0}, raw...)
		}
		return append(append([]byte{2, byte(len(raw))}, raw...), nil...)
	}
	body := append(integer(r), integer(s)...)
	return append(append([]byte{0x30, byte(len(body))}, body...), nil...)
}

// DeriveBchWalletAddress derives a BIP44 BCH address without retaining the
// private key. Mnemonic validation is performed by the caller's wallet; this
// function applies the standard BIP39 seed and BIP32 child derivation.
func DeriveBchWalletAddress(mnemonic, network string, change, index, account uint32, passphrase string, coinType *uint32) (BchWalletAddress, error) {
	if err := validateBip39Mnemonic(mnemonic); err != nil {
		return BchWalletAddress{}, err
	}
	if network != "bch:bitcoincash" && network != "bch:bchtest" {
		return BchWalletAddress{}, fmt.Errorf("unsupported BCH network")
	}
	if change > 1 || account >= 0x80000000 {
		return BchWalletAddress{}, fmt.Errorf("invalid BIP44 derivation index")
	}
	coin := uint32(1)
	if network == "bch:bitcoincash" {
		coin = 145
	}
	if coinType != nil {
		coin = *coinType
	}
	if coin >= 0x80000000 {
		return BchWalletAddress{}, fmt.Errorf("invalid BIP44 coin type")
	}
	seed := pbkdf2HmacSha512([]byte(mnemonic), []byte("mnemonic"+passphrase), 2048, 64)
	master := hmac.New(sha512.New, []byte("Bitcoin seed"))
	master.Write(seed)
	digest := master.Sum(nil)
	key, chain := digest[:32], digest[32:]
	path := []uint32{0x8000002c, coin | 0x80000000, account | 0x80000000, change, index}
	for _, childIndex := range path {
		key, chain = bip32Child(key, chain, childIndex)
	}
	point := secpPointMul(new(big.Int).SetBytes(key), secp256k1G)
	if point == nil {
		return BchWalletAddress{}, fmt.Errorf("invalid derived key")
	}
	publicKey := append([]byte{byte(2 | point.y.Bit(0))}, leftPad32(point.x.Bytes())...)
	script := append([]byte{0x76, 0xa9, 0x14}, hash160(publicKey)...)
	script = append(script, 0x88, 0xac)
	address, err := EncodeCashAddress(script, network, false)
	if err != nil {
		return BchWalletAddress{}, err
	}
	return BchWalletAddress{Address: address, Path: fmt.Sprintf("m/44'/%d'/%d'/%d/%d", coin, account, change, index), Change: change, Index: index, PublicKey: publicKey}, nil
}

func deriveBip44PrivateKey(mnemonic, network, passphrase string, change, index, account uint32) []byte {
	coin := uint32(1)
	if network == "bch:bitcoincash" || network == "mainnet" {
		coin = 145
	}
	seed := pbkdf2HmacSha512([]byte(mnemonic), []byte("mnemonic"+passphrase), 2048, 64)
	master := hmac.New(sha512.New, []byte("Bitcoin seed"))
	master.Write(seed)
	digest := master.Sum(nil)
	key, chain := digest[:32], digest[32:]
	for _, childIndex := range []uint32{0x8000002c, coin | 0x80000000, account | 0x80000000, change, index} {
		key, chain = bip32Child(key, chain, childIndex)
	}
	return key
}

func pbkdf2HmacSha512(password, salt []byte, iterations, length int) []byte {
	result := make([]byte, 0, length)
	for block := 1; len(result) < length; block++ {
		mac := hmac.New(sha512.New, password)
		mac.Write(salt)
		mac.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha512.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		result = append(result, t...)
	}
	return result[:length]
}
func bip32Child(parent, chain []byte, index uint32) ([]byte, []byte) {
	point := secpPointMul(new(big.Int).SetBytes(parent), secp256k1G)
	public := append([]byte{byte(2 | point.y.Bit(0))}, leftPad32(point.x.Bytes())...)
	data := public
	if index >= 0x80000000 {
		data = append([]byte{0}, parent...)
	}
	data = append(data, byte(index>>24), byte(index>>16), byte(index>>8), byte(index))
	mac := hmac.New(sha512.New, chain)
	mac.Write(data)
	digest := mac.Sum(nil)
	scalar := new(big.Int).Add(new(big.Int).SetBytes(digest[:32]), new(big.Int).SetBytes(parent))
	scalar.Mod(scalar, secp256k1N)
	return leftPad32(scalar.Bytes()), digest[32:]
}
func leftPad32(value []byte) []byte {
	result := make([]byte, 32)
	copy(result[32-len(value):], value)
	return result
}

// BchWallet keeps keys and transaction construction outside this package.
