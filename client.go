// Package nessus implements nessus API
package nessus

import (
	"fmt"

	"github.com/hashicorp/go-retryablehttp"
)

const (
	XCookie  = "X-Cookie"
	XApiKeys = "X-ApiKeys"
)

type Client struct {
	req    *retryablehttp.Client
	apiURL string

	// api key
	accessKey string
	secretKey string

	// account
	username string
	password string

	// session token
	token string
}

func NewClient(opts ...Option) *Client {
	c := &Client{
		req:    retryablehttp.NewClient(),
		apiURL: "https://localhost:8834",
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// GetAPIKeys returns the api key in the format of accessKey=accessKey; secretKey=secretKey
func (c *Client) GetAPIKeys() string {
	return fmt.Sprintf("accessKey=%s; secretKey=%s", c.accessKey, c.secretKey)
}

// GetToken returns the session token
func (c *Client) GetToken() string {
	return fmt.Sprintf("token=%s", c.token)
}

func (c *Client) setAuthHeader(req *retryablehttp.Request) {
	if token := c.GetToken(); token != "" {
		req.Header.Set(XCookie, token)
	} else if apiKeys := c.GetAPIKeys(); apiKeys != "" {
		req.Header.Set(XApiKeys, apiKeys)
	}
}
