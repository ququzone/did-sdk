package service

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/ququzone/did-sdk/model"
)

var (
	ErrUnsupportedMethod = errors.New("unsupported method")
)

type Resolver interface {
	Fetch(id string) (*model.Doc, error)
}

type IoTexResolver struct {
	endpoint string
}

func NewIoTeXResolver(endpoint string) *IoTexResolver {
	return &IoTexResolver{endpoint: endpoint}
}

func (r *IoTexResolver) Fetch(id string) (*model.Doc, error) {
	if len(id) != 49 && id[:7] != "did:id:" {
		return nil, ErrUnsupportedMethod
	}
	resp, err := http.Get(r.endpoint + "/did/" + id[7:])
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var doc model.Doc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}
