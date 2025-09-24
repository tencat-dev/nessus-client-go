package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type ScansTimezonesResponse struct {
	Timezones []*Timezones `json:"timezones,omitempty"`
}
type Timezones struct {
	Name    string `json:"name,omitempty"`
	Iana    string `json:"iana,omitempty"`
	Value   string `json:"value,omitempty"`
	Current bool   `json:"current,omitempty"`
}

func (c *Client) ScansTimezones() (*ScansTimezonesResponse, error) {
	resp, err := c.Get(c.apiURL + "/scans/timezones")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, ErrorResponse(body)
	}

	var data ScansTimezonesResponse
	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return &data, nil
}
