package cookie

const (
	nameChar = 1 << iota
	valueChar
	attrChar
)

var chars = [256]uint8{}

func init() {
	for c := 0x20; c < 0x7f; c++ {
		// Valid name chars.
		if c != '(' && c != ')' && c != '<' && c != '>' && c != '@' &&
			c != ',' && c != ';' && c != ':' && c != '\\' && c != '"' &&
			c != '/' && c != '[' && c != ']' && c != '?' && c != '=' &&
			c != '{' && c != '}' && c != ' ' && c != '\t' {
			chars[c] |= nameChar
		}

		// Valid value chars. We treat spaces and commas as valid characters in
		// a cookie value - despite what RFC 2109 says - for pragmatic reasons.
		if c != '"' && c != ';' && c != '\\' {
			chars[c] |= valueChar
		}

		// Valid attribute chars.
		if c != ';' {
			chars[c] |= attrChar
		}
	}
}
