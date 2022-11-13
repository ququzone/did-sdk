package model

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

type VerifiablePresentation struct {
	Context              []string      `json:"@context,omitempty"`
	ID                   string        `json:"id,omitempty"`
	Holder               string        `json:"holder,omitempty"`
	Type                 []string      `json:"type" validate:"required"`
	VerifiableCredential []interface{} `json:"verifiableCredential,omitempty"`
	Proof                *Proof        `json:"proof,omitempty"`
}

func (vp *VerifiablePresentation) Bytes() ([]byte, error) {
	return json.MarshalIndent(vp, "", "  ")
}

func (vp *VerifiablePresentation) Json() (string, error) {
	data, err := vp.Bytes()
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (vp *VerifiablePresentation) Hash() ([]byte, error) {
	temp := &VerifiablePresentation{
		Context:              vp.Context,
		Type:                 vp.Type,
		ID:                   vp.ID,
		Holder:               vp.Holder,
		VerifiableCredential: vp.VerifiableCredential,
	}
	data, err := temp.Bytes()
	if err != nil {
		return nil, err
	}

	return crypto.Keccak256(data), nil
}

func (vc *VerifiablePresentation) VerifyByPrimary() (bool, error) {
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
	return bytes.Equal(common.FromHex(vc.Holder[7:])[:], address[:]), nil
}
