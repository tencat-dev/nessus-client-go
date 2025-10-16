package nessus

import (
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/bytedance/sonic"
)

type ScansDetailsQuery struct {
	HistoryID int
	Limit     int
}

type PermissionResource struct {
	Owner       int    `json:"owner,omitempty"`
	Type        string `json:"type,omitempty"`
	Permissions int    `json:"permissions,omitempty"`
	ID          int    `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
}

type HostResource struct {
	HostID                int    `json:"host_id,omitempty"`
	HostIndex             int    `json:"host_index,omitempty"`
	HostName              string `json:"host_name,omitempty"`
	Progress              string `json:"progress,omitempty"`
	Severity              int    `json:"severity,omitempty"`
	Critical              int    `json:"critical,omitempty"`
	High                  int    `json:"high,omitempty"`
	Medium                int    `json:"medium,omitempty"`
	Low                   int    `json:"low,omitempty"`
	Info                  int    `json:"info,omitempty"`
	Totalchecksconsidered int    `json:"totalchecksconsidered,omitempty"`
	Numchecksconsidered   int    `json:"numchecksconsidered,omitempty"`
	Scanprogresstotal     int    `json:"scanprogresstotal,omitempty"`
	Scanprogresscurrent   int    `json:"scanprogresscurrent,omitempty"`
	Score                 int    `json:"score,omitempty"`
}

type NoteResource struct {
	Type string `json:"title,omitempty"`
	Note []struct {
		Title    string `json:"title,omitempty"`
		Message  string `json:"message,omitempty"`
		Severity int    `json:"severity,omitempty"`
	} `json:"note,omitempty"`
}

type RemediationResource struct {
	Value       string `json:"value,omitempty"`
	Remediation string `json:"remediation,omitempty"`
	Hosts       int    `json:"hosts,omitempty"`
	Vulns       int    `json:"vulns,omitempty"`
}

type VulnerabilityResource struct {
	PluginID      int    `json:"plugin_id,omitempty"`
	PluginName    string `json:"plugin_name,omitempty"`
	PluginFamily  string `json:"plugin_family,omitempty"`
	Count         int    `json:"count,omitempty"`
	VulnIndex     int    `json:"vuln_index,omitempty"`
	SeverityIndex int    `json:"severity_index,omitempty"`
}

type HistoryResource struct {
	HistoryID            int    `json:"history_id,omitempty"`
	UUID                 string `json:"uuid,omitempty"`
	OwnerID              int    `json:"owner_id,omitempty"`
	Status               string `json:"status,omitempty"`
	CreationDate         int    `json:"creation_date,omitempty"`
	LastModificationDate int    `json:"last_modification_date,omitempty"`
}

type FilterResource struct {
	Name         string `json:"name,omitempty"`
	ReadableName string `json:"readable_name,omitempty"`
	Operators    []any  `json:"operators,omitempty"`
	Control      struct {
		Type           string `json:"type,omitempty"`
		ReadableRegest string `json:"readable_regest,omitempty"`
		Regex          string `json:"regex,omitempty"`
		Options        []any  `json:"options"`
	} `json:"control,omitempty"`
}

type ScansDetailsInfo struct {
	Acls            []*PermissionResource `json:"acls,omitempty"`
	EditAllowed     bool                  `json:"edit_allowed,omitempty"`
	Status          ScanStatus            `json:"status,omitempty"`
	Policy          string                `json:"policy,omitempty"`
	PCICanUpload    bool                  `json:"pci-can-upload,omitempty"`
	Hasaudittrail   bool                  `json:"hasaudittrail,omitempty"`
	ScanStart       string                `json:"scan_start,omitempty"`
	FolderID        int                   `json:"folder_id,omitempty"`
	Targets         string                `json:"targets,omitempty"`
	Timestamp       int                   `json:"timestamp,omitempty"`
	ObjectID        int                   `json:"object_id,omitempty"`
	ScannerName     string                `json:"scanner_name,omitempty"`
	Haskb           bool                  `json:"haskb,omitempty"`
	UUID            string                `json:"uuid,omitempty"`
	Hostcount       int                   `json:"hostcount,omitempty"`
	ScanEnd         int                   `json:"scan_end,omitempty"`
	Name            string                `json:"name,omitempty"`
	UserPermissions int                   `json:"user_permissions,omitempty"`
	Control         bool                  `json:"control,omitempty"`
}

type ScansDetailsRemediations struct {
	Remediations      *[]RemediationResource `json:"remediations,omitempty"`
	NumHosts          int                    `json:"num_hosts,omitempty"`
	NumCVEs           int                    `json:"num_cves,omitempty"`
	NumImpactedHosts  int                    `json:"num_impacted_hosts,omitempty"`
	NumRemediatedCVEs int                    `json:"num_remediated_cves,omitempty"`
}

type ScansDetailsResponse struct {
	Info            *ScansDetailsInfo
	Hosts           []*HostResource
	Comphosts       []*HostResource
	Notes           *NoteResource
	Remediations    *ScansDetailsRemediations
	Vulnerabilities []*VulnerabilityResource
	Compliance      []*VulnerabilityResource
	History         []*HistoryResource
	Filters         []*FilterResource
}

func (c *Client) ScansDetails(id int, query *ScansDetailsQuery) (*ScansDetailsResponse, error) {
	param := url.Values{}

	if query.HistoryID != 0 {
		param.Add("history_id", fmt.Sprintf("%d", query.HistoryID))
	}

	if query.Limit != 0 {
		param.Add("limit", fmt.Sprintf("%d", query.Limit))
	}

	apiPath := fmt.Sprintf("/scans/%d", id)
	paramStr := param.Encode()
	if paramStr != "" {
		apiPath = fmt.Sprintf("%s?%s", apiPath, paramStr)
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

	var data ScansDetailsResponse
	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	return &data, nil
}
