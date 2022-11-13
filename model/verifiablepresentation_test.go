package model

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

type DocumentWithKey struct {
	*Doc
	*ecdsa.PrivateKey
}

func GenerateDocument() (*DocumentWithKey, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("convert public key error")
	}
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	doc, err := NewDIDDoc(hex.EncodeToString(publicKeyBytes))
	if err != nil {
		return nil, err
	}

	return &DocumentWithKey{
		Doc:        doc,
		PrivateKey: privateKey,
	}, nil
}

func (d *DocumentWithKey) Address() common.Address {
	return common.HexToAddress(d.Doc.ID[7:])
}

func TestVpVerifyByPrimary(t *testing.T) {
	r := require.New(t)

	// generate did document
	doc1, err := GenerateDocument()
	r.Nil(err)
	doc2, err := GenerateDocument()
	r.Nil(err)

	// issue vc
	vcb := NewVerifiableCredentialBuilder(doc1.ID, doc2.ID)
	vcb.AddContext(VerifiableCredentialsW3bstreamContext)
	vcb.AddType(VerifiableCredentialsW3bstreamContext)
	vcb.AddCredentialSubject(Pair{Key: "readStreamData", Value: "allow"})
	vc, err := vcb.SignSecp256k1HashProof(doc1.PrivateKey)
	r.Nil(err)
	t.Log(vc.Json())

	// verify vc
	verified, err := vc.VerifyByPrimary()
	r.Nil(err)
	r.True(verified)

	// prepare vp
	vpb := NewVerifiablePresentationBuilder(doc2.ID)
	vpb.AddVerifiableCredential(vc)
	vp, err := vpb.SignSecp256k1HashProof(doc2.PrivateKey)
	r.Nil(err)
	t.Log(vp.Json())

	// verify vp
	verified, err = vp.VerifyByPrimary()
	r.Nil(err)
	r.True(verified)
}

func TestStringToVerifiableCredential(t *testing.T) {
	vps := `{
		"@context": [
		  "https://www.w3.org/2018/credentials/v1"
		],
		"id": "urn:uuid:4e79dd09-95ec-403c-a7be-d173b7936f32",
		"holder": "did:io:0xCdbce8Ed49a5125DE495c87BF5FfFb35cee2b323",
		"type": [
		  "VerifiablePresentation"
		],
		"verifiableCredential": [
		  {
			"@context": [
			  "https://www.w3.org/2018/credentials/v1",
			  "https://www.w3.org/2018/credentials/w3bstream/v1"
			],
			"id": "urn:uuid:299187ff-c024-492d-a8be-0ad4b6df6567",
			"type": [
			  "VerifiableCredential",
			  "https://www.w3.org/2018/credentials/w3bstream/v1"
			],
			"issuer": "did:io:0x8e5eebF454FB33FB4d49766EC662B0d3FA1A2Add",
			"issuanceDate": "2022-11-13T20:38:29Z",
			"credentialSubject": {
			  "id": "did:io:0xCdbce8Ed49a5125DE495c87BF5FfFb35cee2b323",
			  "readStreamData": "allow"
			},
			"proof": {
			  "type": "EcdsaSecp256k1Signature2019",
			  "created": "2022-11-13T20:38:29Z",
			  "verificationMethod": "did:io:0x8e5eebF454FB33FB4d49766EC662B0d3FA1A2Add#key-0",
			  "proofPurpose": "assertionMethod",
			  "proofValue": "85d67g23FEJJ8X9kuMYSGA2aw7NrGCnAgscMZftzxGdXfpMUQm7fSqjpsJTkQNsgt9SPm5u7eYNx118ybg4NWZMcL"
			}
		  }
		],
		"proof": {
		  "type": "EcdsaSecp256k1Signature2019",
		  "created": "2022-11-13T20:38:29Z",
		  "verificationMethod": "did:io:0xCdbce8Ed49a5125DE495c87BF5FfFb35cee2b323#key-0",
		  "proofPurpose": "assertionMethod",
		  "proofValue": "8eJzj2cVqMEeUjyY5DnPAKYsa2rUE9z7rMaLwNfeyZgTbm3q7vQijicNEJGixpUM28i2nvSJpW12P1dPRiz1Mp5cj"
		}
	  }
	`
	r := require.New(t)

	vp, err := StringToVerifiablePresentation(vps)
	r.Nil(err)

	r.EqualValues("did:io:0xCdbce8Ed49a5125DE495c87BF5FfFb35cee2b323", vp.Holder)
	r.EqualValues(
		"did:io:0x8e5eebF454FB33FB4d49766EC662B0d3FA1A2Add",
		vp.VerifiableCredential[0].Issuer,
	)
	r.EqualValues(
		"did:io:0xCdbce8Ed49a5125DE495c87BF5FfFb35cee2b323",
		vp.VerifiableCredential[0].CredentialSubject.Get("id"),
	)

	verified, err := vp.VerifyByPrimary()
	r.Nil(err)
	r.True(verified)
}
