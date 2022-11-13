package model

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewDIDDoc(t *testing.T) {
	r := require.New(t)

	doc, err := NewDIDDoc("04830579b50e01602c2015c24e72fbc48bca1cca1e601b119ca73abe2e0b5bd61fcb7874567e091030d6b644f927445d80e00b3f9ca0c566c21c30615e94c343da")

	r.Nil(err)
	r.EqualValues(1, len(doc.Authentication))
	r.EqualValues("did:io:0x8d38efE45794D7FCeeA10b2262C23C12245959dB#key-0", doc.Authentication[0])
}
