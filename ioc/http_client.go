package ioc

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

const (
	errUnexpectedResponse = "unexpected response: %s"
)

type HTTPClient struct{}

var (
	httpClient = HTTPClient{}
)

func (c HTTPClient) getVirustotal(api string) ([]byte, error) {
	req, _ := http.NewRequest("GET", api, nil)
	req.Header.Set("X-Apikey", "7d42532bd1dea1e55f7a8e99cdee23d9b26c386a6485d6dcb4106b9d055f9277")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	c.info(fmt.Sprintf("GET %s -> %d", api, resp.StatusCode))
	if resp.StatusCode != 200 {
		respErr := fmt.Errorf(errUnexpectedResponse, resp.Status)
		fmt.Sprintf("request failed: %v", respErr)
		return nil, respErr
	}
	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}

func (c HTTPClient) getOtx(api string) ([]byte, error) {
	req, _ := http.NewRequest("GET", api, nil)
	req.Header.Set("X-OTX-API-KEY", "779cc51038ddb07c5f6abe0832fed858a6039b9e8cdb167d3191938c1391dbba")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	c.info(fmt.Sprintf("GET %s -> %d", api, resp.StatusCode))
	if resp.StatusCode != 200 {
		respErr := fmt.Errorf(errUnexpectedResponse, resp.Status)
		fmt.Sprintf("request failed: %v", respErr)
		return nil, respErr
	}
	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}

func (c HTTPClient) info(msg string)  {
	log.Printf("[JSONClient] %s\n", msg)
}
