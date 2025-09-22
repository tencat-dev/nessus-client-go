package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type ServerStatusResponse struct {
	Code           int             `json:"code,omitempty"`
	DetailedStatus *DetailedStatus `json:"detailed_status,omitempty"`
	PluginSet      bool            `json:"pluginSet,omitempty"`
	PluginData     bool            `json:"pluginData,omitempty"`
	InitLevel      int             `json:"initLevel,omitempty"`
	Progress       any             `json:"progress,omitempty"`
	Status         string          `json:"status,omitempty"`
}
type FeedStatus struct {
	Progress int    `json:"progress,omitempty"`
	Status   string `json:"status,omitempty"`
}
type DbStatus struct {
	Progress any    `json:"progress,omitempty"`
	Status   string `json:"status,omitempty"`
}
type EngineStatus struct {
	Progress int    `json:"progress,omitempty"`
	Status   string `json:"status,omitempty"`
}
type DetailedStatus struct {
	LoginStatus  string        `json:"login_status,omitempty"`
	FeedStatus   *FeedStatus   `json:"feed_status,omitempty"`
	DbStatus     *DbStatus     `json:"db_status,omitempty"`
	EngineStatus *EngineStatus `json:"engine_status,omitempty"`
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

	if resp.StatusCode != http.StatusOK {
		return nil, ErrorResponse(body)
	}

	var data ServerStatusResponse
	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return &data, nil
}
