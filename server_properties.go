package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type ServerPropertiesResponse struct {
	Md5SumWizardTemplates string `json:"md5sum_wizard_templates,omitempty"`
	NessusType            string `json:"nessus_type,omitempty"`
	UITheme               string `json:"ui_theme,omitempty"`
	Md5SumTenableLinks    string `json:"md5sum_tenable_links,omitempty"`
}

func (c *Client) ServerProperties() (*ServerPropertiesResponse, error) {
	resp, err := c.req.Get(c.apiURL + "/server/properties")
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

	var data ServerPropertiesResponse
	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return &data, nil
}
