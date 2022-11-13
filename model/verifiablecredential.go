package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

var (
	errEmptyProof = errors.New("empty proof")
)

type (
	CredentialSchema struct {
		ID   string `json:"id" validate:"required"`
		Type string `json:"type" validate:"required"`
	}

	Pair struct {
		Key   string
		Value interface{}
	}

	CredentialSubject []Pair

	Proof struct {
		Type               string `json:"type"`
		Created            string `json:"created"`
		VerificationMethod string `json:"verificationMethod"`
		ProofPurpose       string `json:"proofPurpose"`
		ProofValue         string `json:"proofValue"`
	}

	VerifiableCredential struct {
		Context           []string          `json:"@context,omitempty"`
		ID                string            `json:"id,omitempty"`
		Type              []string          `json:"type,omitempty"`
		Issuer            string            `json:"issuer,omitempty"`
		IssuanceDate      string            `json:"issuanceDate,omitempty"`
		ExpirationDate    string            `json:"expirationDate,omitempty"`
		CredentialSubject CredentialSubject `json:"credentialSubject,omitempty"`
		Proof             *Proof            `json:"proof,omitempty"`
	}
)

func (vc *VerifiableCredential) Bytes() ([]byte, error) {
	return json.MarshalIndent(vc, "", "  ")
}

func (vc *VerifiableCredential) Json() (string, error) {
	data, err := vc.Bytes()
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (vc *VerifiableCredential) Hash() ([]byte, error) {
	temp := &VerifiableCredential{
		Context:           vc.Context,
		Type:              vc.Type,
		ID:                vc.ID,
		Issuer:            vc.Issuer,
		IssuanceDate:      vc.IssuanceDate,
		ExpirationDate:    vc.ExpirationDate,
		CredentialSubject: vc.CredentialSubject,
	}
	data, err := temp.Bytes()
	if err != nil {
		return nil, err
	}

	return crypto.Keccak256(data), nil
}

func (vc *VerifiableCredential) VerifyByPrimary() (bool, error) {
	if vc.Proof.ProofValue == "" {
		return false, errEmptyProof
	}
	hash, err := vc.Hash()
	if err != nil {
		return false, err
	}
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n32%s", string(hash))
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write([]byte(msg))
	hash = hasher.Sum(nil)

	pubBytes, err := crypto.Ecrecover(hash, base58.Decode(vc.Proof.ProofValue))
	if err != nil {
		return false, err
	}
	pubKey, err := crypto.UnmarshalPubkey(pubBytes)
	if err != nil {
		return false, err
	}
	address := crypto.PubkeyToAddress(*pubKey)
	if err != nil {
		return false, err
	}
	return bytes.Equal(common.FromHex(vc.Issuer[7:])[:], address[:]), nil
}

func (cs CredentialSubject) Len() int {
	return len(cs)
}

func (cs CredentialSubject) Less(i, j int) bool {
	return cs[i].Key < cs[j].Key
}

func (cs CredentialSubject) Swap(i, j int) {
	cs[i], cs[j] = cs[j], cs[i]
}

func (cs *CredentialSubject) Add(key string, value interface{}) {
	*cs = append(*cs, Pair{key, value})
}

func (cs CredentialSubject) Get(key string) interface{} {
	for _, item := range cs {
		if item.Key == key {
			return item.Value
		}
	}
	return nil
}

func (cs CredentialSubject) MarshalJSON() ([]byte, error) {
	sort.Sort(cs)
	buf := &bytes.Buffer{}
	buf.Write([]byte{'{'})
	for i, item := range cs {
		b, err := json.Marshal(&item.Value)
		if err != nil {
			return nil, err
		}
		buf.WriteString(fmt.Sprintf("%q:", fmt.Sprintf("%v", item.Key)))
		buf.Write(b)
		if i < len(cs)-1 {
			buf.Write([]byte{','})
		}
	}
	buf.Write([]byte{'}'})
	return buf.Bytes(), nil
}

func (cs *CredentialSubject) UnmarshalJSON(b []byte) error {
	m := map[string]Pair{}
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	for k, v := range m {
		*cs = append(*cs, Pair{Key: k, Value: v.Value})
	}
	sort.Sort(*cs)
	return nil
}

func (mi *Pair) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	mi.Value = v
	return nil
}

func StringToVerifiableCredential(data string) (*VerifiableCredential, error) {
	var vc VerifiableCredential

	if err := json.Unmarshal([]byte(data), &vc); err != nil {
		return nil, err
	}
	return &vc, nil
}
