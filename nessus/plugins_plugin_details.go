package nessus

import (
	"fmt"
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type AttributeResource struct {
	AttributeName  string `json:"attribute_name"`
	AttributeValue string `json:"attribute_value"`
}

type PluginsPluginDetailsResponse struct {
	ID         int                 `json:"id"`
	Name       string              `json:"name"`
	FamilyName string              `json:"family_name"`
	Attributes []AttributeResource `json:"attributes"`
}

func (c *Client) PluginsPluginDetails(id int) (*PluginsPluginDetailsResponse, error) {
	resp, err := c.Get(c.apiURL + "/plugins/plugin/" + fmt.Sprint(id))
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

	var data PluginsPluginDetailsResponse

	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	return &data, nil
}
