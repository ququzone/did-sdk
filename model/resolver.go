package model

type Resolver interface {
	Fetch(id string) (*Doc, error)
}

type MemoryResolver struct {
	store map[string]*Doc
}

func NewMemoryResolver() *MemoryResolver {
	return &MemoryResolver{
		store: make(map[string]*Doc),
	}
}

func (r *MemoryResolver) AddByPubkey(pubkey string) (string, error) {
	doc, err := NewDIDDoc(pubkey)
	if err != nil {
		return "", err
	}

	r.store[doc.ID] = doc
	return doc.ID, nil
}

func (r *MemoryResolver) Add(doc *Doc) (string, error) {
	r.store[doc.ID] = doc
	return doc.ID, nil
}

func (r *MemoryResolver) Fetch(id string) (*Doc, error) {
	return r.store[id], nil
}
