package cookie

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// The Cookie struct describes an HTTP cookie.
type Cookie struct {
	Name    string
	Value   string
	Domain  string
	Path    string
	Expires time.Time

	Secure   bool
	HttpOnly bool

	// Relative cookie expiration time. A zero value means no Max-Age attribute
	// was specified, and negative values are used to express "Max-Age=0".
	MaxAge int

	// Unparsed attributes.
	Unparsed []string
}

// Marshal serializes a Cookie.
func (c *Cookie) Marshal(attrs bool) (string, error) {
	if !isValidName(c.Name) {
		return "", fmt.Errorf("cookie.Marshal: invalid cookie name: %q", c.Name)
	}
	if !isValidValue(c.Value) {
		return "", fmt.Errorf("cookie.Marshal: invalid cookie value: %q", c.Value)
	}

	// Short path for when the user doesn't want the cookie's attributes.
	if !attrs {
		if shouldQuoteValue(c.Value) {
			return c.Name + `="` + c.Value + `"`, nil
		} else {
			return c.Name + `=` + c.Value, nil
		}
	}

	// Begin by writing the name and value.
	b := new(bytes.Buffer)
	b.WriteString(c.Name)
	b.WriteByte('=')

	if shouldQuoteValue(c.Value) {
		b.WriteByte('"')
		b.WriteString(c.Value)
		b.WriteByte('"')
	} else {
		b.WriteString(c.Value)
	}

	// Cookie attributes.
	if c.Domain != "" {
		if !isValidDomain(c.Domain) {
			return "", fmt.Errorf("cookie.Marshal: invalid Domain value: %q", c.Domain)
		}
		b.WriteString("; Domain=")
		b.WriteString(c.Domain)
	}

	if c.Path != "" {
		if !isValidAttr(c.Path) {
			return "", fmt.Errorf("cookie.Marshal: invalid Path value: %q", c.Path)
		}
		b.WriteString("; Path=")
		b.WriteString(c.Path)
	}

	if c.Expires.Unix() > 0 {
		// TODO: This is not as efficient as it could be.
		b.WriteString("; Expires=")
		b.WriteString(c.Expires.UTC().Format(time.RFC1123))
	}

	if c.MaxAge > 0 {
		// TODO: This is not as efficient as it could be.
		b.WriteString("; Max-Age=")
		b.WriteString(strconv.Itoa(c.MaxAge))
	} else if c.MaxAge < 0 {
		b.WriteString("; Max-Age=0")
	}

	if c.HttpOnly {
		b.WriteString("; HttpOnly")
	}

	if c.Secure {
		b.WriteString("; Secure")
	}

	// Unparsed attributes.
	for _, attr := range c.Unparsed {
		if !isValidAttr(attr) {
			return "", fmt.Errorf("cookie.Marshal: invalid attribute: %q", attr)
		}
		b.WriteString("; ")
		b.WriteString(attr)
	}

	return b.String(), nil
}

// shouldQuoteValue returns true if the cookie value should be quoted. Matches
// the behavior of package net/http (see http://golang.org/issue/7243).
func shouldQuoteValue(s string) bool {
	first, last := s[0], s[len(s)-1]
	return first == ' ' || first == ',' || last == ' ' || last == ','
}

// Parse parses an HTTP cookie. In the case of a "Cookie" header, each
// semicolon-delimited part should be parsed separately.
func Parse(raw string) (*Cookie, error) {
	s := strings.IndexByte(raw, ';')
	if s < 0 {
		s = len(raw)
	}

	part := trim(raw[:s])

	// Separate the cookie's name and value.
	eq := strings.IndexByte(part, '=')
	if eq < 0 {
		return nil, fmt.Errorf("cookie.Parse: missing cookie value")
	}

	var name = part[:eq]
	var value = part[eq+1:]
	var ok bool

	name, ok = parseName(name)
	if !ok {
		return nil, fmt.Errorf("cookie.Parse: invalid cookie name")
	}

	value, ok = parseValue(value)
	if !ok {
		return nil, fmt.Errorf("cookie.Parse: invalid cookie value")
	}

	c := &Cookie{
		Name:  name,
		Value: value,
	}

	// Parse the cookie's attributes.
	for 0 <= s && s < len(raw) {
		raw = raw[s+1:]

		if s = strings.IndexByte(raw, ';'); s < 0 {
			part = trim(raw)
		} else {
			part = trim(raw[:s])
		}

		if err := parseAttr(c, part); err != nil {
			return nil, err
		}
	}

	return c, nil
}

// parseName validates and parses a cookie name.
func parseName(raw string) (string, bool) {
	if !isValidName(raw) {
		return "", false
	}
	return raw, true
}

// isValidName returns true if the input string is a valid cookie name.
func isValidName(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if chars[s[i]]&nameChar == 0 {
			return false
		}
	}
	return true
}

// parseValue validates and parses a cookie name.
func parseValue(raw string) (string, bool) {
	// Unwrap quotes.
	if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		raw = raw[1 : len(raw)-1]
	}

	// Make sure the value only contains vaild characters.
	if !isValidValue(raw) {
		return "", false
	}

	return raw, true
}

// isValidValue returns true if the input string is a valid cookie value.
func isValidValue(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if chars[s[i]]&valueChar == 0 {
			return false
		}
	}
	return true
}

// parseAttr validates and parses a cookie attribute, then adding it to a
// Cookie struct.
func parseAttr(c *Cookie, raw string) error {
	if !isValidAttr(raw) {
		fmt.Errorf("cookie.Parse: invalid attribute: %q", raw)
	}

	// Separate the value from the key, if there is one.
	var key, val string
	var ok bool

	if eq := strings.IndexByte(raw, '='); eq >= 0 {
		key = raw[:eq]
		val, ok = parseValue(raw[eq+1:])
		if !ok {
			fmt.Errorf("cookie.Parse: invalid attribute: %q", raw)
		}
	} else {
		key = raw
	}

	if key == "" {
		fmt.Errorf("cookie.Parse: invalid attribute: %q", raw)
	}

	// Attribute-specific logic.
	switch key[0] | 0x20 {
	case 'd':
		if len(key) != 6 ||
			key[1]|0x20 != 'o' ||
			key[2]|0x20 != 'm' ||
			key[3]|0x20 != 'a' ||
			key[4]|0x20 != 'i' ||
			key[5]|0x20 != 'n' {
			break
		}

		if !isValidDomain(val[1:]) {
			return fmt.Errorf("cookie.Parse: invalid Domain value: %q", val)
		}

		c.Domain = val
		return nil

	case 'e':
		if len(key) != 7 ||
			key[1]|0x20 != 'x' ||
			key[2]|0x20 != 'p' ||
			key[3]|0x20 != 'i' ||
			key[4]|0x20 != 'r' ||
			key[5]|0x20 != 'e' ||
			key[6]|0x20 != 's' {
			break
		}

		// TODO: This is not as efficient as it could be.
		expires, err := time.Parse(time.RFC1123, val)
		if err != nil {
			expires, err = time.Parse("Mon, 02-Jan-2006 15:04:05 MST", val)
			if err != nil {
				return fmt.Errorf("cookie.Parse: invalid Expires value: %q", val)
			}
		}

		c.Expires = expires
		return nil

	case 'h':
		if len(key) != 8 ||
			key[1]|0x20 != 't' ||
			key[2]|0x20 != 't' ||
			key[3]|0x20 != 'p' ||
			key[4]|0x20 != 'o' ||
			key[5]|0x20 != 'n' ||
			key[6]|0x20 != 'l' ||
			key[7]|0x20 != 'y' {
			break
		}

		c.HttpOnly = true
		return nil

	case 'm':
		if len(key) != 7 ||
			key[1]|0x20 != 'a' ||
			key[2]|0x20 != 'x' ||
			key[3] != '-' ||
			key[4]|0x20 != 'a' ||
			key[5]|0x20 != 'g' ||
			key[6]|0x20 != 'e' {
			break
		}

		// TODO: This is not as efficient as it could be.
		n, err := strconv.Atoi(val)
		if err != nil || n < 0 {
			return fmt.Errorf("cookie.Parse: invalid Max-Age value: %q", val)
		}

		if n == 0 {
			c.MaxAge = -1
		} else {
			c.MaxAge = n
		}
		return nil

	case 'p':
		if len(key) != 4 ||
			key[1]|0x20 != 'a' ||
			key[2]|0x20 != 't' ||
			key[3]|0x20 != 'h' {
			break
		}

		c.Path = val
		return nil

	case 's':
		if len(key) != 6 ||
			key[1]|0x20 != 'e' ||
			key[2]|0x20 != 'c' ||
			key[3]|0x20 != 'u' ||
			key[4]|0x20 != 'r' ||
			key[5]|0x20 != 'e' {
			break
		}

		c.Secure = true
		return nil
	}

	// Store attributes we don't understand in the unparsed slice.
	c.Unparsed = append(c.Unparsed, raw)
	return nil
}

// isValidAttr returns true if the input string is a valid cookie attribute.
func isValidAttr(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if chars[s[i]]&attrChar == 0 {
			return false
		}
	}
	return true
}

// isValidDomain returns true if the input string is is a valid "Domain"
// attribute value.
func isValidDomain(s string) bool {
	return isDomainName(s) || (net.ParseIP(s) != nil && strings.IndexByte(s, ':') < 0)
}

// isDomainName returns true if s is a valid domain name. It is just about
// identical to its namesake in package "net" - the one difference being
// that this version doesn't allow underscores, but allows leading dots.
func isDomainName(s string) bool {
	if len(s) == 0 || len(s) > 255 {
		return false
	}

	if s[0] == '.' {
		s = s[1:]
	}

	var prev byte = '.'
	var ok bool
	var n int

	for i := 0; i < len(s); i++ {
		c := s[i]

		switch {
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z':
			ok = true
			n++

		case '0' <= c && c <= '9':
			n++

		case c == '-':
			if prev == '.' {
				return false
			}
			n++

		case c == '.':
			if prev == '.' || prev == '-' {
				return false
			}
			if n > 63 || n == 0 {
				return false
			}
			n = 0

		default:
			return false
		}

		prev = c
	}

	if prev == '-' || n > 63 {
		return false
	}

	return ok
}

// trim removes leading and trailing whitespace from the input string.
func trim(s string) string {
	l, r := 0, len(s)-1
	for l <= r && (s[l] == ' ' || s[l] == '\t') {
		l++
	}
	for r > l && (s[r] == ' ' || s[r] == '\t') {
		r--
	}
	return s[l : r+1]
}
