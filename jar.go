package cookie

import (
	"errors"
	"net"
	"strings"
	"time"
)

var (
	errInvalidScheme   = errors.New("invalid scheme")
	errNoHostname      = errors.New("no hostname")
	errMalformedDomain = errors.New("malformed domain")
	errIllegalDomain   = errors.New("illegal domain")
)

// PublicSuffixList returns the public suffixes of domains. It is a subset of
// the PublicSuffixList interface defined in package net/http/cookiejar.
type PublicSuffixList interface {
	PublicSuffix(domain string) string
}

// NewJar creates a new cookie jar.
func NewJar(psl PublicSuffixList) *Jar {
	return &Jar{
		psl: psl,
		ent: make(map[string]map[string]*jarEntry),
	}
}

// Jar is a cookie jar.
type Jar struct {
	psl PublicSuffixList
	ent map[string]map[string]*jarEntry
}

// Cookies returns a slice of cookies relevant for the scheme, host and path
// combination.
func (j *Jar) Cookies(scheme, host, path string, now time.Time) ([]*Cookie, error) {
	if scheme != "http" && scheme != "https" {
		return nil, errInvalidScheme
	}

	host, err := canonicalHost(host)
	if err != nil {
		return nil, err
	}

	root := domainRoot(host, j.psl)
	bucket := j.ent[root]

	// Once we've established this domain's bucket, delete expired cookies and
	// output the rest of them.
	var cookies []*Cookie

	for _, entry := range bucket {
		if !entry.Expires.IsZero() && !entry.Expires.After(now) {
			delete(bucket, entry.Domain+";"+entry.Path+";"+entry.Name)
		}

		if entry.shouldSend(scheme, host, path) {
			cookies = append(cookies, &Cookie{
				Name:  entry.Name,
				Value: entry.Value,
			})
		}
	}

	// Remove the bucket if it's now empty.
	if len(bucket) == 0 {
		delete(j.ent, root)
	}

	return cookies, nil
}

// SetCookie updates the jar with a cookie from a "Set-Cookie" header.
func (j *Jar) SetCookie(scheme, host, path string, c *Cookie, now time.Time) error {
	if scheme != "http" && scheme != "https" {
		return errInvalidScheme
	}

	host, err := canonicalHost(host)
	if err != nil {
		return err
	}

	entry, remove, err := newEntry(c, host, j.psl, now)
	if err != nil {
		return err
	}

	// Either save or remove the cookie, depending on when it expires.
	if remove {
		j.remove(entry)
	} else {
		j.set(entry)
	}

	return nil
}

// set creates or overwrites a cookie entry.
func (j *Jar) set(entry *jarEntry) {
	bucket, ok := j.ent[entry.Root]
	if !ok {
		bucket = make(map[string]*jarEntry)
		j.ent[entry.Root] = bucket
	}

	bucket[entry.Key] = entry
}

// remove removes a cookie entry.
func (j *Jar) remove(entry *jarEntry) {
	bucket, ok := j.ent[entry.Root]
	if !ok {
		return
	}

	delete(bucket, entry.Key)
	if len(bucket) == 0 {
		delete(j.ent, entry.Root)
	}
}

// newEntry creates a new jarEntry instance.
func newEntry(c *Cookie, host string, psl PublicSuffixList, now time.Time) (*jarEntry, bool, error) {
	var err error

	entry := &jarEntry{
		Created:  now,
		Name:     c.Name,
		Value:    c.Value,
		Secure:   c.Secure,
		HttpOnly: c.HttpOnly,
	}

	entry.Domain, entry.HostOnly, err = validateDomain(host, c.Domain, psl)
	if err != nil {
		return nil, false, err
	}

	// Ignore invalid paths.
	if c.Path == "" || c.Path[0] != '/' {
		entry.Path = "/"
	} else {
		entry.Path = c.Path
	}

	// Figure out when the cookie is scheduled to expire.
	// Max-Age takes prescendence over Expires.
	if c.MaxAge < 0 {
		return entry, true, nil
	} else if c.MaxAge > 0 {
		entry.Expires = now.Add(time.Duration(c.MaxAge) * time.Second)
	} else if !c.Expires.IsZero() {
		if c.Expires.After(now) {
			entry.Expires = c.Expires
		} else {
			return entry, true, nil
		}
	}

	// Populate bookkeeping fields.
	entry.Root = domainRoot(host, psl)
	entry.Key = entry.Domain + ";" + entry.Path + ";" + entry.Name

	return entry, false, nil
}

// A jarEntry adds some bookkeeping metadata to a reduced Cookie.
type jarEntry struct {
	Root string
	Key  string

	Created  time.Time
	Expires  time.Time
	HostOnly bool

	// Subset of the Cookie type.
	Name     string
	Value    string
	Domain   string
	Path     string
	Secure   bool
	HttpOnly bool
}

// shouldSend returns true if the cookie entry is relevant for requests to
// the scheme, host and path combination.
func (entry *jarEntry) shouldSend(scheme, host, path string) bool {
	if entry.Secure && scheme != "https" {
		return false
	}

	if entry.Domain != host && (entry.HostOnly || !hasDotSuffix(host, entry.Domain)) {
		return false
	}

	if path != entry.Path {
		if !strings.HasPrefix(path, entry.Path) {
			return false
		}
		if entry.Path[len(entry.Path)-1] != '/' && path[len(entry.Path)] != '/' {
			return false
		}
	}

	return true
}

// validateDomain validates a cookie domain name, and make sure it falls under
// the specified hostname given a public suffix list.
func validateDomain(host, domain string, psl PublicSuffixList) (string, bool, error) {
	if domain == "" {
		return host, true, nil
	}

	if isIP(host) {
		return "", false, errNoHostname
	}

	// We allow (and ignore) a single leading dot. After that, though, domains
	// which are either empty or have leading or trailing dots are considered
	// malformed.
	if domain[0] == '.' {
		domain = domain[1:]
	}
	if domain == "" || domain[0] == '.' || domain[len(domain)-1] == '.' {
		return "", false, errMalformedDomain
	}

	domain = strings.ToLower(domain)

	if psl != nil {
		suffix := psl.PublicSuffix(domain)
		if suffix != "" && !hasDotSuffix(domain, suffix) {
			// If the domain itself is a public suffix this is a host cookie,
			// otherwise the Set-Cookie operation is illegal.
			if host == domain {
				return host, true, nil
			} else {
				return "", false, errIllegalDomain
			}
		}

		// Make sure this cookie isn't being set for a different domain.
		if host != domain && !hasDotSuffix(host, domain) {
			return "", false, errIllegalDomain
		}
	}

	return domain, false, nil
}

// canonicalHost canonicalizes a hostname.
func canonicalHost(host string) (string, error) {
	host = strings.ToLower(host)

	if hasPort(host) {
		var err error

		host, _, err = net.SplitHostPort(host)
		if err != nil {
			return "", err
		}
	}

	return toASCII(host)
}

// domainRoot returns the domain root for a particular host. For example,
// "example.com" in the case of "foo.bar.example.com".
func domainRoot(host string, psl PublicSuffixList) string {
	if isIP(host) {
		return host
	}

	if psl != nil {
		suffix := psl.PublicSuffix(host)
		if suffix == host {
			return host
		}

		// Guard against bad implementations.
		i := len(host) - len(suffix)
		if i > 0 && host[i-1] == '.' {
			return host[strings.LastIndex(host[:i-1], ".")+1:]
		}
	}

	return ""
}

// isIP returns true if host is an IP address.
func isIP(host string) bool {
	return net.ParseIP(host) != nil
}

// hasPort returns true if addr contains a port number.
func hasPort(addr string) bool {
	if len(addr) == 0 {
		return false
	}

	var colons int
	var rbrack bool

	for i, c := range addr {
		if c == ':' {
			colons++
			rbrack = addr[i-1] == ']'
		}
	}

	switch colons {
	case 0:
		return false
	case 1:
		return true
	default:
		return addr[0] == '[' && rbrack
	}
}

// hasDotSuffix returns true if s ends in "."+suffix.
func hasDotSuffix(s, suffix string) bool {
	return len(s) > len(suffix) && s[len(s)-len(suffix)-1] == '.' &&
		s[len(s)-len(suffix):] == suffix
}
