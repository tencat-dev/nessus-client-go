package nessus

import (
	"fmt"

	"github.com/hashicorp/go-retryablehttp"
)

// Option represents a functional option for configuring the Client.
type Option func(*Client) error

// WithRequest sets a custom retryablehttp.Client for the Client.
func WithRequest(req *retryablehttp.Client) Option {
	return func(c *Client) error {
		if req == nil {
			return fmt.Errorf("request must not nil")
		}

		c.req = req
		return nil
	}
}
