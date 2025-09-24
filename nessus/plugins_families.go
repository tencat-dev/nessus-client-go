package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type FamilyResource struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type PluginsFamiliesResponse struct {
	Families []FamilyResource `json:"families"`
}

func (c *Client) PluginsFamilies() (*PluginsFamiliesResponse, error) {
	resp, err := c.Get(c.getAPIURL("/plugins/families"))
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

	var data PluginsFamiliesResponse

	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	return &data, nil
}
