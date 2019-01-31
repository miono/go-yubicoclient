package yubicoclient

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())

}

// Client is the client used to make requests to yubicloud
type Client struct {
	apiAccount string
	apiSecret  string
	apiServers []string
	uri        string
	sl         int
}

// New returns a new instance of a Client
func New(apiAccount string, apiSecret string, apiServers []string, uri string) (*Client, error) {
	return &Client{
		apiAccount: apiAccount,
		apiSecret:  apiSecret,
		apiServers: apiServers,
		uri:        uri,
	}, nil
}

// DefaultClient returns a new instance of a default client with the default API-servers
func DefaultClient(apiAccount string, apiSecret string) (*Client, error) {
	yc, err := New(apiAccount, apiSecret, []string{"api.yubico.com", "api2.yubico.com", "api3.yubico.com", "api4.yubico.com", "api5.yubico.com"}, "/wsapi/2.0/verify")
	if err != nil {
		panic(err)
	}
	return yc, nil
}

// SetSL śets the required servicelevel
func (c *Client) SetSL(sl int) error {
	if sl < 0 || sl > 100 {
		return errors.New("Service level must be between 0 and 100")
	}
	c.sl = sl
	return nil
}

// Verify verifies the OTP caught from the yubikey, it returns true if the key is valid and false if it's not
func (c *Client) Verify(otp string) (bool, Error) {
	// Build the requests
	reqs, _ := c.buildRequests(otp)
	responseChannel := make(chan yubicloudResponse)
	errorChannel := make(chan yubicloudResponse)
	ctx, cancelContext := context.WithCancel(context.Background())
	var response yubicloudResponse
	var errors []yubicloudResponse
	for _, req := range reqs {
		go c.doRequest(ctx, req, responseChannel, errorChannel)
	}
LOOP:
	for i := 0; i < len(reqs); i++ {
		select {
		case response = <-responseChannel:
			break LOOP
		case err := <-errorChannel:
			errors = append(errors, err)
		}
	}
	cancelContext()
	// At this point we have one response in response and n errors in the errors-slice

	// Checking if all our requests rendered errors
	if len(errors) == len(c.apiServers) {
		return false, decideError(errors)
	}

	if response.otp == otp && response.status == "OK" {
		return true, nil
	}
	return false, nil
}

func (c *Client) doRequest(ctx context.Context, req yubicloudRequest, responseChannel chan<- yubicloudResponse, errorChannel chan<- yubicloudResponse) {
	fmt.Println(req.url.String())
	response, err := http.Get(req.url.String())
	if err != nil {
		errorChannel <- yubicloudResponse{respError: ConnectionError{host: req.url.Host, severity: 9, errorMsg: "Couldn't contact server"}}
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		errorChannel <- yubicloudResponse{respError: HTTPError{host: req.url.Host, severity: 8, errorMsg: strconv.Itoa(response.StatusCode)}}
		return
	}
	resp, err2 := parseResponse(c, response.Body)
	if err2 != nil {
		errorChannel <- yubicloudResponse{respError: err2}
	}
	if resp.status == "OK" {
		responseChannel <- resp
	} else {
		errorChannel <- resp
	}
	return
}

func parseResponse(c *Client, r io.Reader) (yubicloudResponse, Error) {
	scanner := bufio.NewScanner(r)
	values := make(map[string]string)
	for scanner.Scan() != false {
		data := strings.Split(scanner.Text(), "=")
		values[data[0]] = strings.Join(data[1:], "=")
	}
	sl, err := strconv.Atoi(values["sl"])
	if err != nil {
		sl = 0
	}
	response := yubicloudResponse{
		otp:       values["otp"],
		status:    values["status"],
		hmac:      values["h"],
		timestamp: values["t"],
		nonce:     values["nonce"],
		sl:        sl,
	}
	switch response.status {
	case "OK":
		return response, nil
	case "BAD_OTP":
		response.respError = OTPError{severity: 1, errorMsg: "BAD_OTP, this OTP isn't valid"}
	case "REPLAYED_OTP":
		response.respError = OTPError{severity: 2, errorMsg: "REPLAYED_OTP, this OTP has previously been seen by the server"}
	case "REPLAYED_REQUEST":
		response.respError = OTPError{severity: 3, errorMsg: "REPLAYED_REQUEST, this OTP has previously been seen by the server"}
	case "BAD_SIGNATURE":
		response.respError = ClientError{severity: 4, errorMsg: "BAD_SIGNATURE, your id/secret is probably wrong"}
	case "NO_SUCH_CLIENT":
		response.respError = ClientError{severity: 5, errorMsg: "NO_SUCH_CLIENT, the clientID doesn't exist"}
	case "OPERATION_NOT_ALLOWED":
		response.respError = ClientError{severity: 6, errorMsg: "OPERATION_NOT_ALLOWED, this clientID isn't allowed to verify tokens"}
	default:
		response.respError = UnknownError{severity: 7, errorMsg: "Unknown status from server"}
	}
	return response, nil

}

func (c *Client) buildRequests(otp string) ([]yubicloudRequest, error) {
	var reqs []yubicloudRequest
	for _, server := range c.apiServers {
		v := url.Values{}
		v.Add("otp", otp)
		v.Add("nonce", generateNonce())
		v.Add("id", c.apiAccount)
		v.Add("h", createHMAC(v, c.apiSecret))
		req := yubicloudRequest{
			url: url.URL{
				Scheme:   "https",
				Host:     server,
				Path:     c.uri,
				RawQuery: v.Encode(),
			},
		}
		reqs = append(reqs, req)
	}

	return reqs, nil
}

func generateNonce() string {
	availableChars := "abcdefghijklmnopqrstuvwxyz"
	nonceLen := rand.Intn(24) + 16
	output := make([]byte, nonceLen)

	for i := range output {
		output[i] = availableChars[rand.Intn(len(availableChars))]

	}
	return string(output)
}

type yubicloudRequest struct {
	client *Client
	url    url.URL
}

func createHMAC(values url.Values, apiSecret string) string {
	decodedKey, _ := base64.StdEncoding.DecodeString(apiSecret)
	h := hmac.New(sha1.New, []byte(decodedKey))
	h.Write([]byte(values.Encode()))
	ba := h.Sum(nil)
	sEnc := base64.StdEncoding.EncodeToString(ba)
	return sEnc

}

type yubicloudResponse struct {
	hmac      string
	nonce     string
	otp       string
	sl        int // SyncLevel
	status    string
	timestamp string
	respError Error
}

// Error is fulfilled by the different error-types
type Error interface {
	Error() string
	getSeverity() int
}

// ConnectionError is emitted if it wasn't possible to contact any of the servers
type ConnectionError struct {
	severity int
	host     string
	errorMsg string
}

func (ce ConnectionError) Error() string {
	return ce.errorMsg
}

func (ce ConnectionError) getSeverity() int {
	return ce.severity
}

// HTTPError is emitted if no server responded with HTTP OK.
type HTTPError struct {
	severity int
	host     string
	errorMsg string
}

func (he HTTPError) Error() string {
	return he.errorMsg
}

func (he HTTPError) getSeverity() int {
	return he.severity
}

// OTPError is emitted if the OTP supplied wasn't valid
type OTPError struct {
	severity int
	errorMsg string
}

func (oe OTPError) Error() string {
	return oe.errorMsg
}

func (oe OTPError) getSeverity() int {
	return oe.severity
}

// ClientError is emitted if the client-ID or client-secret wasn't valid.
type ClientError struct {
	severity int
	errorMsg string
}

func (ce ClientError) Error() string {
	return ce.errorMsg
}

func (ce ClientError) getSeverity() int {
	return ce.severity
}

// UnknownError happens when we get a reply from the servers with a status we don't recognize
type UnknownError struct {
	severity int
	errorMsg string
}

func (ue UnknownError) Error() string {
	return ue.errorMsg
}

func (ue UnknownError) getSeverity() int {
	return ue.severity
}

func decideError(ycrs []yubicloudResponse) Error {
	leastSevere := yubicloudResponse{respError: UnknownError{severity: 100}}

	for _, ycr := range ycrs {
		if ycr.respError.getSeverity() < leastSevere.respError.getSeverity() {
			leastSevere = ycr
		}

	}
	return leastSevere.respError

}
