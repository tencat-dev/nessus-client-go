package nessus

import (
	"net/http"

	"github.com/hashicorp/go-retryablehttp"
)

func (c *Client) Get(url string) (*http.Response, error) {
	req, err := retryablehttp.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	c.setAuthHeader(req)
	return c.req.Do(req)
}

func (c *Client) Post(url, bodyType string, body any) (*http.Response, error) {
	req, err := retryablehttp.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", bodyType)
	c.setAuthHeader(req)
	return c.req.Do(req)
}

func (c *Client) Put(url, bodyType string, body any) (*http.Response, error) {
	req, err := retryablehttp.NewRequest("PUT", url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", bodyType)
	c.setAuthHeader(req)
	return c.req.Do(req)
}

func (c *Client) Delete(url, bodyType string, body any) (*http.Response, error) {
	req, err := retryablehttp.NewRequest("DELETE", url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", bodyType)
	c.setAuthHeader(req)
	return c.req.Do(req)
}
