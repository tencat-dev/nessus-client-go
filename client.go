package nessus

import (
	"github.com/hashicorp/go-retryablehttp"
)

type Client struct {
	req *retryablehttp.Client
}

func NewClient(opts ...Option) *Client {
	c := &Client{
		req: retryablehttp.NewClient(),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}
