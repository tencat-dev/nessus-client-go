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

		c.WithRequest(req)
		return nil
	}
}

// WithRequest sets a custom retryablehttp.Client for the Client.
func (c *Client) WithRequest(req *retryablehttp.Client) {
	c.req = req
}

// WithAPIURL sets the base API URL for the Client.
func WithAPIURL(apiURL string) Option {
	return func(c *Client) error {
		parsed, err := url.Parse(apiURL)
		if err != nil {
			return err
		}

		parsed.Path = strings.TrimRight(parsed.Path, "/")
		c.WithAPIURL(parsed.String())
		return nil
	}
}

// WithAPIURL sets the base API URL for the Client.
func (c *Client) WithAPIURL(apiURL string) {
	c.apiURL = apiURL
}

// WithAccount sets the username and password for the Client.
func WithAccount(username string, password string) Option {
	return func(c *Client) error {
		if username == "" || password == "" {
			return fmt.Errorf("username or password must not nil")
		}

		c.WithAccount(username, password)
		return nil
	}
}

// WithAccount sets the username and password for the Client.
func (c *Client) WithAccount(username string, password string) {
	c.username = username
	c.password = password
}

// WithAPIKey sets the accessKey and secretKey for the Client.
func WithAPIKey(accessKey string, secretKey string) Option {
	return func(c *Client) error {
		if accessKey == "" || secretKey == "" {
			return fmt.Errorf("accessKey or secretKey must not nil")
		}

		c.WithAPIKey(accessKey, secretKey)
		return nil
	}
}

// WithAPIKey sets the accessKey and secretKey for the Client.
func (c *Client) WithAPIKey(accessKey string, secretKey string) {
	c.accessKey = accessKey
	c.secretKey = secretKey
}

// WithToken sets the session token for the Client.
func WithToken(token string) Option {
	return func(c *Client) error {
		if token == "" {
			return fmt.Errorf("token must not nil")
		}

		c.WithToken(token)
		return nil
	}
}

// WithToken sets the session token for the Client.
func (c *Client) WithToken(token string) {
	c.token = token
}
