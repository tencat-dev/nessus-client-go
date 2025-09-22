package nessus

import (
	"github.com/hashicorp/go-retryablehttp"
)

type Client struct {
	req       *retryablehttp.Client
	apiURL    string
	accessKey string
	secretKey string
	username  string
	password  string
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
