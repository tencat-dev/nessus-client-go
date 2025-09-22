package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type ServerStatusResponse struct {
	Code           int `json:"code,omitempty"`
	DetailedStatus struct {
		LoginStatus string `json:"login_status,omitempty"`
		FeedStatus  struct {
			Progress int    `json:"progress,omitempty"`
			Status   string `json:"status,omitempty"`
		} `json:"feed_status,omitempty"`
		DbStatus struct {
			Progress any    `json:"progress,omitempty"`
			Status   string `json:"status,omitempty"`
		} `json:"db_status,omitempty"`
		EngineStatus struct {
			Progress int    `json:"progress,omitempty"`
			Status   string `json:"status,omitempty"`
		} `json:"engine_status,omitempty"`
	} `json:"detailed_status,omitempty"`
	PluginSet  bool   `json:"pluginSet,omitempty"`
	PluginData bool   `json:"pluginData,omitempty"`
	InitLevel  int    `json:"initLevel,omitempty"`
	Progress   any    `json:"progress,omitempty"`
	Status     string `json:"status,omitempty"`
}

func (c *Client) ServerStatus() (*ServerStatusResponse, error) {
	resp, err := c.req.Get(c.apiURL + "/server/status")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, ErrorResponse(body)
	}

	var data ServerStatusResponse
	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return &data, nil
}
