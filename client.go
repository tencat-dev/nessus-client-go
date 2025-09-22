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

func (c *Client) ApiKeys() string {
	return fmt.Sprintf("accessKey=%s; secretKey=%s", c.accessKey, c.secretKey)
}

func (c *Client) Token() string {
	return c.token
}
