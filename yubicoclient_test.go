package yubicoclient

import (
	"math/rand"
	"net/url"
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
			// t.Errorf("buildRequests with input: %v was incorrect, got %v, want %v", table.otp, testOutput, table.output)
			t.Errorf("\n\n%v\n\n%v", testOutput[0], testOutput[1])
		}
	}
}
