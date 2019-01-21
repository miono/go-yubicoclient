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
func (c *Client) Verify(otp string) (bool, error) {
	// Build the requests
	reqs, _ := c.buildRequests(otp)
	responseChannel := make(chan yubicloudResponse)
	errorChannel := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	// fmt.Println(reqs)
	var response yubicloudResponse
	var errors []error
	for _, req := range reqs {
		go c.doRequest(ctx, req, responseChannel, errorChannel)
	}
	for i := 0; i < len(c.apiServers); i++ {
		select {
		case response = <-responseChannel:
			break
		case err := <-errorChannel:
			errors = append(errors, err)
		}
	}
	cancel()
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

func (c *Client) doRequest(ctx context.Context, req yubicloudRequest, responseChannel chan<- yubicloudResponse, errorChannel chan<- error) {
	response, err := http.Get(req.getURL())
	if err != nil {
		errorChannel <- fmt.Errorf("Couldn't contact server %s", req.apiServer)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		errorChannel <- fmt.Errorf("Status was not 200 from server %s", req.apiServer)
	}
	resp, err := parseResponse(response.Body)
	if err != nil {
		panic(err)
	}
	responseChannel <- resp

}

func parseResponse(r io.Reader) (yubicloudResponse, error) {
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
	fmt.Println(url)
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
}
