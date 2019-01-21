package yubicoclient

import (
	"bufio"
	"context"
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

// Verify verifies the OTP caught from the yubikey, it returns true if the key is valid and false if it's not
func (c *Client) Verify(OTP string) (bool, error) {
	// Build the requests
	reqs, _ := c.buildRequests(OTP)
	responseChannel := make(chan yubicloudResponse)
	errorChannel := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	fmt.Println(reqs)
	var response yubicloudResponse
	var errors []error
	for _, req := range reqs {
		go c.doRequest(ctx, req, responseChannel, errorChannel)
	}
	for i := 0; i < len(c.apiServers); i++ {
		select {
		case response = <-responseChannel:
			cancel()
			break
		case err := <-errorChannel:
			errors = append(errors, err)
		}
	}
	for _, err := range errors {
		fmt.Println(err)
	}
	if response.OTP == OTP && response.status == "OK" {
		return true, nil
	}
	return false, nil
}

func (c *Client) doRequest(ctx context.Context, req yubicloudRequest, responseChannel chan<- yubicloudResponse, errorChannel chan<- error) {
	response, err := http.Get(req.URL)
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
		OTP:       values["otp"],
		status:    values["status"],
		hmac:      values["h"],
		timestamp: values["t"],
		nonce:     values["nonce"],
		sl:        sl,
	}
	return response, nil

}

func (c *Client) buildRequests(OTP string) ([]yubicloudRequest, error) {
	var reqs []yubicloudRequest
	for _, server := range c.apiServers {
		reqs = append(reqs, yubicloudRequest{
			URL:       server + c.uri + "?" + "id=" + c.apiAccount + "&nonce=hejkalleankaboll&otp=" + OTP,
			apiServer: server,
		})

	}
	return reqs, nil

}

type yubicloudRequest struct {
	URL       string
	apiServer string
}

type yubicloudResponse struct {
	hmac      string
	timestamp string
	OTP       string
	nonce     string
	sl        int // SyncLevel
	status    string
}
