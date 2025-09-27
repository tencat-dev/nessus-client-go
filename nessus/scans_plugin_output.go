package nessus

import (
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/bytedance/sonic"
)

type ScansPluginOutputInfo struct {
	Plugindescription struct {
		Severity         int    `json:"severity,omitempty"`
		Pluginname       string `json:"pluginname,omitempty"`
		Pluginattributes struct {
			RiskInformation struct {
				RiskFactor string `json:"risk_factor,omitempty"`
			} `json:"risk_information,omitempty"`
			PluginName        string `json:"plugin_name,omitempty"`
			PluginInformation struct {
				PluginID               int    `json:"plugin_id,omitempty"`
				PluginType             string `json:"plugin_type,omitempty"`
				PluginFamily           string `json:"plugin_family,omitempty"`
				PluginModificationDate string `json:"plugin_modification_date,omitempty"`
			} `json:"plugin_information,omitempty"`
			Solution    string `json:"solution,omitempty"`
			Fname       string `json:"fname,omitempty"`
			Synopsis    string `json:"synopsis,omitempty"`
			Description string `json:"description,omitempty"`
		} `json:"pluginattributes,omitempty"`
		PluginFamily string `json:"plugin_family,omitempty"`
		PluginID     string `json:"plugin_id,omitempty"`
	} `json:"plugindescription,omitempty"`
}

type ScansPluginOutputQuery struct {
	HistoryID *int
}

type ScansPluginOutputPathParams struct {
	ScanID   int
	HostID   int
	PluginID int
}

type PluginOutput struct {
	PluginOutput string            `json:"plugin_output,omitempty"`
	Hosts        string            `json:"hosts,omitempty"`
	Severiry     int               `json:"severiry,omitempty"`
	Ports        map[string]string `json:"ports,omitempty"`
}

type ScansPluginOutputResponse struct {
	Info   *ScansPluginOutputInfo
	Output []*PluginOutput
}

func (c *Client) ScansPluginOutput(pathParam *ScansPluginOutputPathParams, query *ScansPluginOutputQuery) (*ScansPluginOutputResponse, error) {
	params := url.Values{}

	if query.HistoryID != nil {
		params.Add("history_id", fmt.Sprintf("%d", *query.HistoryID))
	}

	apiPath := fmt.Sprintf("/scans/%d/hosts/%d/plugins/%d", pathParam.ScanID, pathParam.HostID, pathParam.PluginID)
	queryStr := params.Encode()

	if queryStr != "" {
		apiPath = fmt.Sprintf("%s?%s", apiPath, queryStr)
	}

	resp, err := c.Get(c.getAPIURL(apiPath))
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

	var data ScansPluginOutputResponse

	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	return &data, nil
}
