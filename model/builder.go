package model

import (
	"crypto/ecdsa"
	"fmt"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"golang.org/x/crypto/sha3"
)

const (
	UUIDPrefix                             string = "urn:uuid:"
	VerifiableCredentialsLinkedDataContext string = "https://www.w3.org/2018/credentials/v1"
	VerifiableCredentialsW3bstreamContext  string = "https://www.w3.org/2018/credentials/w3bstream/v1"
	VerifiableCredentialType               string = "VerifiableCredential"
	W3bServiceCredentialType               string = "W3bServiceCredential"
	VerifiableCredentialIDProperty         string = "id"
	VerifiablePresentationType             string = "VerifiablePresentation"
)

type (
	// VerifiableCredentialBuilder builder for VerifiableCredential
	VerifiableCredentialBuilder struct {
		*VerifiableCredential
	}

	// VerifiablePresentationBuilder builder for VerifiablePresentation
	VerifiablePresentationBuilder struct {
		*VerifiablePresentation
	}
)

func NewVerifiableCredentialBuilder(issuer, holder string) *VerifiableCredentialBuilder {
	return &VerifiableCredentialBuilder{
		&VerifiableCredential{
			Context: []string{
				VerifiableCredentialsLinkedDataContext,
			},
			ID: UUIDPrefix + uuid.New().String(),
			Type: []string{
				VerifiableCredentialType,
			},
			Issuer:       issuer,
			IssuanceDate: time.Now().Format("2006-01-02T15:04:05Z"),
			CredentialSubject: &CredentialSubject{
				Pair{Key: "id", Value: holder},
			},
		},
	}
}

func (b *VerifiableCredentialBuilder) AddContext(context string) {
	b.Context = append(b.Context, context)
}

func (b *VerifiableCredentialBuilder) AddType(typeS string) {
	b.Type = append(b.Type, typeS)
}

func (b *VerifiableCredentialBuilder) AddCredentialSubject(pair Pair) {
	*b.CredentialSubject = append(*b.CredentialSubject, pair)
}

func (b *VerifiableCredentialBuilder) Build() *VerifiableCredential {
	return b.VerifiableCredential
}

func (b *VerifiableCredentialBuilder) SignSecp256k1HashProof(privateKey *ecdsa.PrivateKey) (*VerifiableCredential, error) {
	hash, err := b.Hash()
	if err != nil {
		return nil, err
	}
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n32%s", string(hash))
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write([]byte(msg))
	hash = hasher.Sum(nil)

	signature, err := crypto.Sign(hash, privateKey)
	if err != nil {
		return nil, err
	}
	b.Proof = &Proof{
		Type:               "EcdsaSecp256k1Signature2019",
		Created:            time.Now().Format("2006-01-02T15:04:05Z"),
		ProofPurpose:       "assertionMethod",
		VerificationMethod: b.Issuer + "#key-0",
		ProofValue:         base58.Encode(signature),
	}
	return b.VerifiableCredential, nil
}

func NewVerifiablePresentationBuilder(holder string) *VerifiablePresentationBuilder {
	return &VerifiablePresentationBuilder{
		&VerifiablePresentation{
			Context: []string{
				VerifiableCredentialsLinkedDataContext,
			},
			ID: UUIDPrefix + uuid.New().String(),
			Type: []string{
				VerifiablePresentationType,
			},
			Holder: holder,
		},
	}
}

func (b *VerifiablePresentationBuilder) AddVerifiableCredential(vc *VerifiableCredential) {
	b.VerifiableCredential = append(b.VerifiableCredential, vc)
}

func (b *VerifiablePresentationBuilder) SignSecp256k1HashProof(privateKey *ecdsa.PrivateKey) (*VerifiablePresentation, error) {
	hash, err := b.Hash()
	if err != nil {
		return nil, err
	}
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n32%s", string(hash))
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write([]byte(msg))
	hash = hasher.Sum(nil)

	signature, err := crypto.Sign(hash, privateKey)
	if err != nil {
		return nil, err
	}
	b.Proof = &Proof{
		Type:               "EcdsaSecp256k1Signature2019",
		Created:            time.Now().Format("2006-01-02T15:04:05Z"),
		ProofPurpose:       "assertionMethod",
		VerificationMethod: b.Holder + "#key-0",
		ProofValue:         base58.Encode(signature),
	}
	return b.VerifiablePresentation, nil
}
