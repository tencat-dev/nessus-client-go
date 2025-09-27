package nessus

import (
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/bytedance/sonic"
)

type ScansHostDetailsQuery struct {
	HistoryID int
}

type ScansHostDetailsPathParams struct {
	ScanID int
	HostID int
}

type ScansHostDetailsInfo struct {
	HostStart       string `json:"host_start,omitempty"`
	MacAddress      string `json:"mac-address,omitempty"`
	HostFqdn        string `json:"host_fqdn,omitempty"`
	HostEnd         string `json:"host_end,omitempty"`
	OperatingSystem string `json:"operating_system,omitempty"`
	HostIP          string `json:"host-ip,omitempty"`
}

type HostComplianceResource struct {
	HostID        int    `json:"host_id,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	PluginID      int    `json:"plugin_id,omitempty"`
	PluginName    string `json:"plugin_name,omitempty"`
	PluginFamily  string `json:"plugin_family,omitempty"`
	Count         int    `json:"count,omitempty"`
	SeverityIndex int    `json:"severity_index,omitempty"`
	Severity      int    `json:"severity,omitempty"`
}

type HostVulnerabilityResource struct {
	HostComplianceResource `json:"host_compliance_resource,omitempty"`
	VulnIndex              int `json:"vuln_index,omitempty"`
}

type ScansHostDetailsResponse struct {
	Info            *ScansHostDetailsInfo
	Compliance      []*HostComplianceResource
	Vulnerabilities []*HostVulnerabilityResource
}

func (c *Client) ScansHostDetails(pathParam *ScansHostDetailsPathParams, query *ScansHostDetailsQuery) (*ScansHostDetailsResponse, error) {
	params := url.Values{}

	if query.HistoryID != 0 {
		params.Add("history_id", fmt.Sprintf("%d", query.HistoryID))
	}

	apiPath := fmt.Sprintf("/scans/%d/hosts/%d", pathParam.ScanID, pathParam.HostID)
	queryStr := params.Encode()

	if queryStr != "" {
		apiPath = fmt.Sprintf("%s?%s", apiPath, queryStr)
	}

	resp, err := c.Get(c.getAPIURL("%s", apiPath))
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

	var data ScansHostDetailsResponse

	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	return &data, nil
}
