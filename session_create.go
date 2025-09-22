package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type SessionCreateRequest struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type SessionCreateResponse struct {
	Md5SumWizardTemplates string `json:"md5sum_wizard_templates,omitempty"`
	Token                 string `json:"token,omitempty"`
	Md5SumTenableLinks    string `json:"md5sum_tenable_links,omitempty"`
}

func (c *Client) SessionCreate() (*SessionCreateResponse, error) {
	reqBody, err := sonic.Marshal(&SessionCreateRequest{
		Username: c.username,
		Password: c.password,
	})
	if err != nil {
		return nil, err
	}

	resp, err := c.req.Post(c.apiURL+"/session", "application/json", reqBody)
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

	var data SessionCreateResponse
	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return &data, nil
}
