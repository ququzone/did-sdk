package model

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewVerifiableCredentialBuilder(t *testing.T) {
	r := require.New(t)

	builder := NewVerifiableCredentialBuilder(
		"did:io:0x8d38efE45794D7FCeeA10b2262C23C12245959dB",
		"did:io:0x7F8dEAd26586BAfA7c262171F9970e4281996026",
	)

	json, err := builder.Build().Json()
	r.Nil(err)
	t.Log(json)
}
