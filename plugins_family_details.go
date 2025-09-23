package nessus

import (
	"fmt"
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type PluginResource struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type PluginsFamilyDetailsResponse struct {
	ID      int              `json:"id"`
	Name    string           `json:"name"`
	Plugins []PluginResource `json:"plugins"`
}

func (c *Client) PluginsFamilyDetails(id int) (*PluginsFamilyDetailsResponse, error) {
	resp, err := c.Get(c.apiURL + "/plugins/families/" + fmt.Sprint(id))
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

	var data PluginsFamilyDetailsResponse

	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	return &data, nil
}
