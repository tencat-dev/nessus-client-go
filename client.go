// Package nessus implements nessus API
package nessus

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/hashicorp/go-retryablehttp"
)

const (
	xCookie  = "X-Cookie"
	xApiKeys = "X-ApiKeys"
)

// Client represents a client for interacting with the Nessus API
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

// NewClient creates a new Client
func NewClient(opts ...Option) (*Client, error) {
	req := retryablehttp.NewClient()
	req.HTTPClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	c := &Client{
		req:    req,
		apiURL: "https://localhost:8834",
	}
	for _, o := range opts {
		if err := o(c); err != nil {
			return nil, err
		}
	}
	return c, nil
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
	if c.accessKey != "" && c.secretKey != "" {
		req.Header.Set(xApiKeys, c.GetAPIKeys())
	} else if c.token != "" {
		req.Header.Set(xCookie, c.GetToken())
	}
}
