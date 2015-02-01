package cookie

import (
	"errors"
	"strings"
)

var (
	errInvalidDomain = errors.New("invalid domain")
)

const (
	base int32 = 36
	damp int32 = 700
	skew int32 = 38
	tmax int32 = 26
	tmin int32 = 1

	initialBias int32 = 72
	initialN    int32 = 128
)

// toASCII converts a domain or domain label to its ASCII form.
func toASCII(domain string) (string, error) {
	if isASCII(domain) {
		return domain, nil
	}

	labels := strings.Split(domain, ".")
	buf := make([]byte, 0, 512)

	for i := range labels {
		if isASCII(labels[i]) {
			continue
		}

		var err error

		labels[i], err = encode(labels[i], buf)
		if err != nil {
			return "", err
		}
	}

	return strings.Join(labels, "."), nil
}

// isASCII returns true if the input string contains only ASCII characters.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}

	return true
}

// encode converts a non-ASCII domain label to its punycode representation.
func encode(s string, buf []byte) (string, error) {
	var bias = initialBias
	var n = initialN

	var d, b, h, m int32
	var q, k, t int32
	var rem int

	// Begin by writing the "ASCII Compatible Encoding" prefix.
	buf = append(buf, "xn--"...)

	// Copy all ASCII characters from the input, and count the number of
	// non-ASCII runes.
	for _, r := range s {
		if r < 0x80 {
			b++
			buf = append(buf, byte(r))
		} else {
			rem++
		}
	}

	// Append the separator if the input contained any ASCII characters.
	if b > 0 {
		buf = append(buf, '-')
	}

	h = b

	// Encode each non-ASCII character.
	for rem > 0 {
		// Find the minimum rune >= n in the input.
		m = 0x7fffffff
		for _, r := range s {
			if m > r && r >= n {
				m = r
			}
		}

		d = d + ((m - n) * (h + 1))
		n = m

		if d < 0 {
			return "", errInvalidDomain
		}

		// Encode the next non-ASCII character.
		for _, r := range s {
			if r < n {
				if d++; d < 0 {
					return "", errInvalidDomain
				}
				continue
			}
			if r > n {
				continue
			}

			q = d
			k = base

			for {
				if t = k - bias; t < tmin {
					t = tmin
				} else if t > tmax {
					t = tmax
				}

				if q < t {
					break
				}

				if digit := t + ((q - t) % (base - t)); digit < 26 {
					buf = append(buf, byte('a'+digit))
				} else {
					buf = append(buf, byte('0'-26+digit))
				}

				q = (q - t) / (base - t)
				k = k + base
			}

			if digit := q; digit < 26 {
				buf = append(buf, byte('a'+digit))
			} else {
				buf = append(buf, byte('0'-26+digit))
			}

			bias = adapt(d, h+1, h == b)
			d = 0
			h = h + 1
			rem--
		}

		d++
		n++
	}

	return string(buf), nil
}

// adapt is the bias adaption function from RFC 3492, 6.1.
func adapt(delta, points int32, first bool) int32 {
	if first {
		delta /= damp
	} else {
		delta /= 2
	}

	delta += delta / points
	k := int32(0)

	for delta > ((base-tmin)*tmax)/2 {
		delta /= base - tmin
		k += base
	}

	return k + (base-tmin+1)*delta/(delta+skew)
}
