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

// YubiClient is the client used to make requests to yubicloud
type YubiClient struct {
	apiAccount string
	apiSecret  string
	apiServers []string
	uri        string
}

// NewYubiClient returns a new instance of a YubiClient
func NewYubiClient(apiAccount string, apiSecret string, apiServers []string, uri string) (*YubiClient, error) {
	return &YubiClient{
		apiAccount: apiAccount,
		apiSecret:  apiSecret,
		apiServers: apiServers,
		uri:        uri,
	}, nil
}

// NewDefaultYubiClient returns a new instance of a default client with the default API-servers
func NewDefaultYubiClient(apiAccount string, apiSecret string) (*YubiClient, error) {
	yc, err := NewYubiClient(apiAccount, apiSecret, []string{"https://api.yubico.com", "https://api2.yubico.com"}, "/wsapi/2.0/verify")
	if err != nil {
		panic(err)
	}
	return yc, nil
}

// Verify verifies the OTP caught from the yubikey, it returns true if the key is valid and false if it's not
func (yc *YubiClient) Verify(OTP string) (bool, error) {
	// Build the requests
	reqs, _ := yc.buildRequests(OTP)
	responseChannel := make(chan yubicloudResponse)
	ctx, cancel := context.WithCancel(context.Background())
	fmt.Println(reqs)
	for _, req := range reqs {
		go yc.doRequest(ctx, req, responseChannel)
	}
	fmt.Println(<-responseChannel)
	cancel()

	return false, nil
}

func (yc *YubiClient) doRequest(ctx context.Context, req yubicloudRequest, responseChannel chan<- yubicloudResponse) {
	response, err := http.Get(req.URL)
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()
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

func (yc *YubiClient) buildRequests(OTP string) ([]yubicloudRequest, error) {
	var reqs []yubicloudRequest
	for _, server := range yc.apiServers {
		reqs = append(reqs, yubicloudRequest{
			URL: server + yc.uri + "?" + "id=" + yc.apiAccount + "&nonce=hejkalleankaboll&otp=" + OTP,
		})

	}
	return reqs, nil

}

type yubicloudRequest struct {
	URL string
}

type yubicloudResponse struct {
	hmac      string
	timestamp string
	OTP       string
	nonce     string
	sl        int // SyncLevel
	status    string
}
