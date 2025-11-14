package enchantrix

// Sigil defines the interface for a data transformer.
// A Sigil is a reversible or irreversible transformation of a byte slice.
type Sigil interface {
	// In transforms the data.
	In(data []byte) ([]byte, error)
	// Out reverses the transformation.
	Out(data []byte) ([]byte, error)
}

// Enchantrix defines the interface for acceptance testing.
type Enchantrix interface {
	Transmute(data []byte, sigils []Sigil) ([]byte, error)
}

// Transmute is a helper function for applying a series of sigils to data.
func Transmute(data []byte, sigils []Sigil) ([]byte, error) {
	var err error
	for _, sigil := range sigils {
		data, err = sigil.In(data)
		if err != nil {
			return nil, err
		}
	}
	return data, nil
}
