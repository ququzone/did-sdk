package model

import (
	"crypto/ecdsa"
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBasicCredentialSubject(t *testing.T) {
	cs := new(CredentialSubject)

	cs.Add("z", "zipper")
	cs.Add("hello", "world")
	cs.Add("a", "upper")

	data, err := json.Marshal(cs)

	assert.Nil(t, err)
	assert.Equal(t, `{"a":"upper","hello":"world","z":"zipper"}`, string(data))

	var tcs CredentialSubject
	err = json.Unmarshal(data, &tcs)
	assert.Nil(t, err)

	assert.Nil(t, tcs.Get("no"))
	assert.Equal(t, 3, tcs.Len())
	assert.Equal(t, "world", tcs.Get("hello"))
}

func TestVerifyByPrimary(t *testing.T) {
	r := require.New(t)

	privateKey, err := crypto.GenerateKey()
	r.Nil(err)
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	r.True(ok)
	address := crypto.PubkeyToAddress(*publicKeyECDSA)

	builder := NewVerifiableCredentialBuilder(
		"did:io:"+address.Hex(),
		"did:id:0x8d38efE45794D7FCeeA10b2262C23C12245959dB",
	)
	builder.AddContext(VerifiableCredentialsW3bstreamContext)
	builder.AddType(VerifiableCredentialsW3bstreamContext)
	builder.AddCredentialSubject(Pair{Key: "readStreamData", Value: "allow"})

	vc, err := builder.SignSecp256k1HashProof(privateKey)
	r.Nil(err)
	t.Log(vc.Json())

	verified, err := vc.VerifyByPrimary()
	r.Nil(err)
	r.True(verified)
}
