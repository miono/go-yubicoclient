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
	"net/http"
	"strconv"
	"strings"
)

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
	yc, err := New(apiAccount, apiSecret, []string{"http://flaffapuppakungballe.com", "http://lagga.se", "https://api.yubico.com", "https://api2.yubico.com", "https://api3.yubico.com", "https://api4.yubico.com", "https://api5.yubico.com"}, "/wsapi/2.0/verify")
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
	// fmt.Println(reqs)
	var response yubicloudResponse
	var errors []error
	for _, req := range reqs {
		go c.doRequest(ctx, req, responseChannel, errorChannel)
	}
LOOP:
	for i := 0; i < len(reqs); i++ {
		select {
		case response = <-responseChannel:
			break LOOP
		case err := <-errorChannel:
			errors = append(errors, err.respError)
		}
	}
	cancelContext()
	if len(errors) == len(c.apiServers) {
		return false, fmt.Errorf("No servers replied with status 200")
	}
	for _, err := range errors {
		fmt.Println(err)
	}

	if response.otp == otp && response.status == "OK" {
		return true, nil
	}
	return false, nil
}

func (c *Client) doRequest(ctx context.Context, req yubicloudRequest, responseChannel chan<- yubicloudResponse, errorChannel chan<- yubicloudResponse) {
	response, err := http.Get(req.getURL())
	if err != nil {
		fmt.Println("Having problems contacting server")
		errorChannel <- yubicloudResponse{respError: ConnectionError{host: req.apiServer, errorMsg: "Couldn't contact server"}}
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		fmt.Println("not getting 200")
		errorChannel <- yubicloudResponse{respError: HTTPError{host: req.apiServer, errorMsg: strconv.Itoa(response.StatusCode)}}
		return
	}
	resp, err := parseResponse(response.Body, req.apiServer)
	if err != nil {
		errorChannel <- yubicloudResponse{respError: err}
	}
	if resp.status == "OK" {
		responseChannel <- resp
	} else {
		errorChannel <- resp
	}
	return
}

func parseResponse(r io.Reader, host string) (yubicloudResponse, Error) {
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
		return response, OTPError{host: host, errorMsg: "BAD_OTP"}
	case "REPLAYED_OTP":
		return response, OTPError{host: host, errorMsg: "REPLAYED_OTP"}
	case "BAD_SIGNATURE":
		return response, ClientError{host: host, errorMsg: "BAD_SIGNATURE"}
	case "NO_SUCH_CLIENT":
		return response, ClientError{host: host, errorMsg: "NO_SUCH_CLIENT"}
	case "OPERATION_NOT_ALLOWED":
		return response, ClientError{host: host, errorMsg: "OPERATION_NOT_ALLOWED"}
	}

	fmt.Println(response)
	return response, nil

}

func (c *Client) buildRequests(otp string) ([]yubicloudRequest, error) {
	var reqs []yubicloudRequest
	for _, server := range c.apiServers {
		reqs = append(reqs, yubicloudRequest{
			client:    c,
			apiServer: server,
			uri:       c.uri,
			otp:       otp,
			nonce:     "hejkalleankaboll",
			timestamp: false,
		})

	}
	return reqs, nil

}

type yubicloudRequest struct {
	client    *Client
	apiServer string
	uri       string
	otp       string
	nonce     string
	timestamp bool
	hmac      string
	sl        int
}

func (ycr *yubicloudRequest) getURL() string {
	unsignedURI := "id=" + ycr.client.apiAccount + "&nonce=" + ycr.nonce + "&otp=" + ycr.otp
	ycr.hmac = ycr.createHMAC(unsignedURI)
	url := ycr.apiServer + ycr.uri + "?" + unsignedURI + "&h=" + ycr.hmac
	return url
}

func (ycr *yubicloudRequest) createHMAC(unsignedURI string) string {
	decodedKey, _ := base64.StdEncoding.DecodeString(ycr.client.apiSecret)
	h := hmac.New(sha1.New, []byte(decodedKey))
	h.Write([]byte(unsignedURI))
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
}

// ConnectionError is emitted if it wasn't possible to contact any of the servers
type ConnectionError struct {
	host     string
	errorMsg string
}

func (ce ConnectionError) Error() string {
	return ce.errorMsg
}

// HTTPError is emitted if no server responded with HTTP OK.
type HTTPError struct {
	host     string
	errorMsg string
}

func (he HTTPError) Error() string {
	return he.errorMsg
}

// OTPError is emitted if the OTP supplied wasn't valid
type OTPError struct {
	host     string
	errorMsg string
}

func (oe OTPError) Error() string {
	return oe.errorMsg
}

// ClientError is emitted if the client-ID or client-secret wasn't valid.
type ClientError struct {
	host     string
	errorMsg string
}

func (ce ClientError) Error() string {
	return ce.errorMsg
}
