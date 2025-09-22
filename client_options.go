package nessus

import (
	"fmt"
	"net/url"
	"strings"

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

// WithApiURL sets the base API URL for the Client.
func WithApiURL(apiUrl string) Option {
	return func(c *Client) error {
		parsed, err := url.Parse(apiUrl)
		if err != nil {
			return err
		}

		parsed.Path = strings.TrimRight(parsed.Path, "/")
		c.apiURL = parsed.String()
		return nil
	}

}

// WithAccount sets the username and password for the Client.
func WithAccount(username string, password string) Option {
	return func(c *Client) error {
		if username == "" || password == "" {
			return fmt.Errorf("username or password must not nil")
		}

		c.username = username
		c.password = password
		return nil
	}
}

// WithApiKey sets the accessKey and secretKey for the Client.
func WithApiKey(accessKey string, secretKey string) Option {
	return func(c *Client) error {
		if accessKey == "" || secretKey == "" {
			return fmt.Errorf("accessKey or secretKey must not nil")
		}

		c.accessKey = accessKey
		c.secretKey = secretKey
		return nil
	}
}
