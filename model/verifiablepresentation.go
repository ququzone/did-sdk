package model

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ququzone/did-sdk/base58"
	"golang.org/x/crypto/sha3"
)

type VerifiablePresentation struct {
	Context              []string                `json:"@context,omitempty"`
	ID                   string                  `json:"id,omitempty"`
	Holder               string                  `json:"holder,omitempty"`
	Type                 []string                `json:"type" validate:"required"`
	VerifiableCredential []*VerifiableCredential `json:"verifiableCredential,omitempty"`
	Proof                *Proof                  `json:"proof,omitempty"`
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

func (vp *VerifiablePresentation) VerifyByPrimary(vcv func(*VerifiableCredential) (bool, error)) (bool, error) {
	if vp.Proof.ProofValue == "" {
		return false, errEmptyProof
	}
	hash, err := vp.Hash()
	if err != nil {
		return false, err
	}
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n32%s", string(hash))
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write([]byte(msg))
	hash = hasher.Sum(nil)

	pubBytes, err := crypto.Ecrecover(hash, base58.Decode(vp.Proof.ProofValue))
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
	if !bytes.Equal(common.FromHex(vp.Holder[7:]), address[:]) {
		return false, errInvalidProof
	}
	for _, vc := range vp.VerifiableCredential {
		if valid, err := vc.VerifyByPrimary(); !valid || err != nil {
			return false, err
		}
		if vc.CredentialSubject.Get("id") != vp.Holder {
			return false, errFakeIssuer
		}
		if valid, err := vcv(vc); !valid || err != nil {
			return false, err
		}
	}

	return true, nil
}

func (vp *VerifiablePresentation) Verify(resolver Resolver, vcv func(*VerifiableCredential) (bool, error)) (bool, error) {
	if vp.Proof.ProofValue == "" {
		return false, errEmptyProof
	}

	doc, err := resolver.Fetch(vp.Holder)
	if err != nil {
		return false, err
	}
	vm := doc.GetVerificationMethod(vp.Proof.VerificationMethod)
	if vm == nil {
		return false, errEmptyVerificationMethod
	}

	hash, err := vp.Hash()
	if err != nil {
		return false, err
	}
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n32%s", string(hash))
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write([]byte(msg))
	hash = hasher.Sum(nil)

	pubBytes, err := crypto.Ecrecover(hash, base58.Decode(vp.Proof.ProofValue))
	if err != nil {
		return false, err
	}
	pubKey, err := crypto.UnmarshalPubkey(pubBytes)
	if err != nil {
		return false, err
	}
	compressedPubKey := crypto.CompressPubkey(pubKey)
	if base58.Encode(compressedPubKey) != vm.PublicKeyBase58 {
		return false, errInvalidProof
	}

	for _, vc := range vp.VerifiableCredential {
		if valid, err := vc.Verify(resolver); !valid || err != nil {
			return false, err
		}
		if vc.CredentialSubject.Get("id") != vp.Holder {
			return false, errFakeIssuer
		}
		if valid, err := vcv(vc); !valid || err != nil {
			return false, err
		}
	}

	return true, nil
}

func StringToVerifiablePresentation(data string) (*VerifiablePresentation, error) {
	var vp VerifiablePresentation

	if err := json.Unmarshal([]byte(data), &vp); err != nil {
		return nil, err
	}
	return &vp, nil
}
