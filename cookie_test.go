package cookie

import (
	"reflect"
	"testing"
	"time"
)

var parseTests = []struct {
	in  string
	out *Cookie
	err error
}{
	{
		" foo=bar ",
		&Cookie{
			Name:  "foo",
			Value: "bar",
		},
		nil,
	},
	{
		"PREF=ID=eb6cda4781936022:U=481e4b712990588c:FF=4:LD=en:TM=1402393637:LM=1414704417:SG=2:S=3xbMSGb_nnYBD-J3; Max-Age=0; SECURE",
		&Cookie{
			Name:   "PREF",
			Value:  "ID=eb6cda4781936022:U=481e4b712990588c:FF=4:LD=en:TM=1402393637:LM=1414704417:SG=2:S=3xbMSGb_nnYBD-J3",
			MaxAge: -1,
			Secure: true,
		},
		nil,
	},
	{
		"NID=99=YsDT5i3E-CXax-; expires=Wed, 23-Nov-2011 01:05:03 UTC; path=/; domain=.google.ch; HttpOnly",
		&Cookie{
			Name:     "NID",
			Value:    "99=YsDT5i3E-CXax-",
			Path:     "/",
			Domain:   ".google.ch",
			HttpOnly: true,
			Expires:  time.Date(2011, 11, 23, 1, 5, 3, 0, time.UTC),
		},
		nil,
	},
	{
		".ASPXAUTH=7E3AA; expires=Wed, 07-Mar-2012 14:25:06 UTC; path=/; HttpOnly",
		&Cookie{
			Name:     ".ASPXAUTH",
			Value:    "7E3AA",
			Path:     "/",
			Expires:  time.Date(2012, 3, 7, 14, 25, 6, 0, time.UTC),
			HttpOnly: true,
		},
		nil,
	},
	{
		"ASP.NET_SessionId=foo; path=/; HttpOnly",
		&Cookie{
			Name:     "ASP.NET_SessionId",
			Value:    "foo",
			Path:     "/",
			HttpOnly: true,
		},
		nil,
	},
	{
		"foo=bar; httponly",
		&Cookie{
			Name:     "foo",
			Value:    "bar",
			HttpOnly: true,
		},
		nil,
	},
	{
		"baz=qux; Http-Only",
		&Cookie{
			Name:     "baz",
			Value:    "qux",
			Unparsed: []string{"Http-Only"},
		},
		nil,
	},

	// Weird ones.
	{`x=a z`, &Cookie{Name: "x", Value: "a z"}, nil},
	{`x=" z"`, &Cookie{Name: "x", Value: " z"}, nil},
	{`x="a "`, &Cookie{Name: "x", Value: "a "}, nil},
	{`x=" "`, &Cookie{Name: "x", Value: " "}, nil},
	{`x=a,z`, &Cookie{Name: "x", Value: "a,z"}, nil},
	{`x=",z"`, &Cookie{Name: "x", Value: ",z"}, nil},
	{`x=a,`, &Cookie{Name: "x", Value: "a,"}, nil},
	{`x=","`, &Cookie{Name: "x", Value: ","}, nil},
}

func TestParse(t *testing.T) {
	for _, test := range parseTests {
		out, err := Parse(test.in)
		if !reflect.DeepEqual(out, test.out) || !reflect.DeepEqual(err, test.err) {
			t.Errorf("Parse(%#q):", test.in)
			t.Errorf("  got  %+v, %+v", out, err)
			t.Errorf("  want %+v, %+v", test.out, test.err)
		}
	}
}

var marshalTests = []struct {
	in  *Cookie
	out string
	err error
}{
	{
		&Cookie{
			Name:     "foo",
			Value:    "=bar=baz=quux=",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
		},
		"foo==bar=baz=quux=; Max-Age=0; HttpOnly; Secure",
		nil,
	},
	{
		&Cookie{
			Name:     "foo",
			Value:    "bar",
			Domain:   ".example.com",
			MaxAge:   3600,
			HttpOnly: true,
		},
		"foo=bar; Domain=.example.com; Max-Age=3600; HttpOnly",
		nil,
	},
	{
		&Cookie{
			Name:     "some",
			Value:    "cookie",
			Domain:   ".example.com",
			Unparsed: []string{"foo=123", "bar"},
		},
		"some=cookie; Domain=.example.com; foo=123; bar",
		nil,
	},
	{
		&Cookie{
			Name:    "x",
			Value:   "y",
			Path:    "/foo/",
			Expires: time.Date(2011, 11, 23, 1, 5, 3, 0, time.UTC),
		},
		"x=y; Path=/foo/; Expires=Wed, 23 Nov 2011 01:05:03 UTC",
		nil,
	},

	// Weird ones.
	{&Cookie{Name: "x", Value: "a z"}, `x=a z`, nil},
	{&Cookie{Name: "x", Value: " z"}, `x=" z"`, nil},
	{&Cookie{Name: "x", Value: "a "}, `x="a "`, nil},
	{&Cookie{Name: "x", Value: " "}, `x=" "`, nil},
	{&Cookie{Name: "x", Value: "a,z"}, `x=a,z`, nil},
	{&Cookie{Name: "x", Value: ",z"}, `x=",z"`, nil},
	{&Cookie{Name: "x", Value: "a,"}, `x="a,"`, nil},
	{&Cookie{Name: "x", Value: ","}, `x=","`, nil},
}

func TestMarshal(t *testing.T) {
	for _, test := range marshalTests {
		out, err := test.in.Marshal(true)
		if !reflect.DeepEqual(out, test.out) || !reflect.DeepEqual(err, test.err) {
			t.Errorf("(%+v).Marshal(true):", test.in)
			t.Errorf("  got  %#q, %+v", out, err)
			t.Errorf("  want %#q, %+v", test.out, test.err)
		}
	}
}
