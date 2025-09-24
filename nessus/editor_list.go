package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type EditorListResponse struct {
	Templates []*Templates `json:"templates,omitempty"`
}

type Templates struct {
	Unsupported      bool   `json:"unsupported,omitempty"`
	LicenseFulfilled bool   `json:"license_fulfilled,omitempty"`
	Desc             string `json:"desc,omitempty"`
	Order            int    `json:"order,omitempty"`
	SubscriptionOnly bool   `json:"subscription_only,omitempty"`
	IsWas            bool   `json:"is_was,omitempty"`
	Title            string `json:"title,omitempty"`
	IsAgent          bool   `json:"is_agent,omitempty"`
	UUID             string `json:"uuid,omitempty"`
	DynamicScan      bool   `json:"dynamic_scan,omitempty"`
	Icon             string `json:"icon,omitempty"`
	ManagerOnly      bool   `json:"manager_only,omitempty"`
	Category         string `json:"category,omitempty"`
	Name             string `json:"name,omitempty"`
	MoreInfo         string `json:"more_info,omitempty"`
}

func (c *Client) EditorList(editorType EditorType) (*EditorListResponse, error) {
	resp, err := c.Get(c.apiURL + "/editor/" + string(editorType) + "/templates")
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

	var data EditorListResponse
	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return &data, nil
}
