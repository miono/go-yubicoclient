package yubicoclient

import (
	"log"
	"math/rand"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestDefaultClient(t *testing.T) {
	c, err := DefaultClient("123", "string")
	if err != nil {
		t.Errorf("Couldn't create client")
	}
	if c.apiSecret != "string" {
		t.Errorf("apiSecret mismatched on created client")
	}
	if c.apiAccount != "123" {
		t.Errorf("apiAccount mismatched on created client")
	}

}

func TestCreateHMAC(t *testing.T) {
	tables := []struct {
		input     string
		apiSecret string
		output    string
	}{
		{
			input:     "test",
			apiSecret: "test",
			output:    "me50L1BneaefWlbvb/XpsaIclo0=",
		},
	}
	for _, table := range tables {
		testOutput := createHMAC(table.input, table.apiSecret)
		if testOutput != table.output {
			t.Errorf("createHMAC with input: %v and apiSecret %v was incorrect, got %v, want %v", table.input, table.apiSecret, testOutput, table.output)
		}

	}
}

func TestCheckOTP(t *testing.T) {
	tables := []struct {
		otp   string
		valid bool
	}{
		{
			otp:   "tooshort",
			valid: false,
		},
		{
			otp:   "toolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolong",
			valid: false,
		},
		{
			otp:   "cbdefghijklnrtuvcbdefghijklnrtuv",
			valid: true,
		},
		{
			otp:   "stringcontai\tnsincorrectcharacters",
			valid: false,
		},
	}
	for _, table := range tables {
		testOutput := checkOTP(table.otp)
		if testOutput != table.valid {
			t.Errorf("checkOTP with input: %v was incorrect, got %v, want %v", table.otp, testOutput, table.valid)
		}
	}
}

func TestBuildRequests(t *testing.T) {
	testClient := New("1234", "test", []string{"example1.local", "example2.local"}, "/testpath")
	rand.Seed(1) // Seeding with 1 to get same nonce every time
	tables := []struct {
		otp    string
		output []url.URL
	}{
		{
			otp: "cbdefghijklnrtuvcbdefghijklnrtuv",
			output: []url.URL{
				url.URL{
					Scheme:   "https",
					Host:     "example1.local",
					Path:     "/testpath",
					RawQuery: "h=U2rPaPvm1iFyrRiWvgJ5C6I8emk%3D&id=1234&nonce=vlbzgbaicmrajwwhthctcuaxhxkqfdafp&otp=cbdefghijklnrtuvcbdefghijklnrtuv",
				},
				url.URL{
					Scheme:   "https",
					Host:     "example2.local",
					Path:     "/testpath",
					RawQuery: "h=TtRDpMRG%2B9dgrGGUAOsFRPDX5b8%3D&id=1234&nonce=sjfbcxoeffrswxpldnjobcsnvlgtemapezqle&otp=cbdefghijklnrtuvcbdefghijklnrtuv",
				},
			},
		},
	}
	for _, table := range tables {
		testOutput := testClient.buildRequests(table.otp)
		if !cmp.Equal(testOutput, table.output) {
			t.Errorf("buildRequests with input: %v was incorrect, got %v, want %v", table.otp, testOutput, table.output)
		}
	}
}

func TestGenerateNonce(t *testing.T) {
	testOutput := generateNonce()
	if len(testOutput) > 40 || len(testOutput) < 16 {
		t.Errorf("generateNonce generated a nonce of wrong length")
	}
	allowedChars := "abcdefghijklmnopqrstuvwxyz"
	for _, oc := range testOutput {
		if !strings.ContainsRune(allowedChars, oc) {
			t.Errorf("generated nonce contained invalid character %v", oc)
		}
	}
}

func TestParseResponse(t *testing.T) {
	testClient := New("1234", "secret", []string{"hej", "hoj"}, "hupp")
	tables := []struct {
		req      url.URL
		response string
		output   yubicloudResponse
	}{
		{
			req: url.URL{
				Scheme:   "https",
				RawQuery: "otp=cbdefghijklnrtuvcbdefghijklnrtuv&nonce=abcdefghijklmnopqrstuvwxyz",
			},
			response: `
h=TryezWlZK4wIH4Tohodk0FH52ow=
t=2019-03-03T11:49:59Z0739
otp=cbdefghijklnrtuvcbdefghijklnrtuv
nonce=abcdefghijklmnopqrstuvwxyz
sl=25
status=OK
`,
			output: yubicloudResponse{
				hmac:      "TryezWlZK4wIH4Tohodk0FH52ow=",
				timestamp: "2019-03-03T11:49:59Z0739",
				nonce:     "abcdefghijklmnopqrstuvwxyz",
				otp:       "cbdefghijklnrtuvcbdefghijklnrtuv",
				status:    "OK",
				sl:        25,
				respError: nil,
			},
		},
	}

	for _, table := range tables {
		testOutput := parseResponse(testClient, table.req, strings.NewReader(table.response))
		if !cmp.Equal(testOutput, table.output, cmp.AllowUnexported(testOutput)) {
			log.Println(testOutput.hmac)
			t.Errorf("parseResponse with input %v was incorrect. Got %v, want %v", table.response, testOutput, table.output)

		}
	}

}
