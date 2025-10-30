package nessus

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/bytedance/sonic"
)

type ScansPluginOutputInfo struct {
	Plugindescription struct {
		Severity         int    `json:"severity,omitempty"`
		Pluginname       string `json:"pluginname,omitempty"`
		Pluginattributes struct {
			RiskInformation map[string]string `json:"risk_information,omitempty"`
			RefInformation  struct {
				Ref []struct {
					Name   string `json:"name"`
					Values struct {
						Value []string `json:"value"`
					} `json:"values"`
					URL string `json:"url"`
				} `json:"ref"`
			} `json:"ref_information"`
			PluginName        string `json:"plugin_name,omitempty"`
			PluginInformation struct {
				PluginID               int    `json:"plugin_id,omitempty"`
				PluginType             string `json:"plugin_type,omitempty"`
				PluginFamily           string `json:"plugin_family,omitempty"`
				PluginModificationDate string `json:"plugin_modification_date,omitempty"`
			} `json:"plugin_information,omitempty"`
			Solution        string   `json:"solution,omitempty"`
			Fname           string   `json:"fname,omitempty"`
			Synopsis        string   `json:"synopsis,omitempty"`
			Description     string   `json:"description,omitempty"`
			SeeAlso         []string `json:"see_also,omitempty"`
			VPRScore        string   `json:"vpr_score,omitempty"`
			EPSSScore       string   `json:"epss_score,omitempty"`
			VulnInformation struct {
				InTheNews            string    `json:"in_the_news,omitempty"`
				AssetInventory       string    `json:"asset_inventory,omitempty"`
				VulnPublicationDate  time.Time `json:"vuln_publication_date,omitempty"`
				PatchPublicationDate time.Time `json:"patch_publication_date,omitempty"`
				ExploitabilityEase   string    `json:"exploitability_ease,omitempty"`
				ExploitAvailable     string    `json:"exploit_available,omitempty"`
				UnsupportedByVendor  string    `json:"unsupported_by_vendor,omitempty"`
				Impact               string    `json:"impact,omitempty"`
				CPE                  string    `json:"cpe,omitempty"`
			} `json:"vuln_information"`
		} `json:"pluginattributes,omitempty"`
		PluginFamily string `json:"plugin_family,omitempty"`
		PluginID     string `json:"plugin_id,omitempty"`
	} `json:"plugindescription,omitempty"`
}

type ScansPluginOutputQuery struct {
	HistoryID int
}

type ScansPluginOutputPathParams struct {
	ScanID   int
	HostID   int
	PluginID int
}

type PluginOutput struct {
	MaxAttachmentsExceeded bool           `json:"max_attachments_exceeded,omitempty"`
	Ports                  map[string]any `json:"ports,omitempty"`
	HasAttachment          any            `json:"has_attachment,omitempty"`
	Hosts                  any            `json:"hosts,omitempty"`
	Severity               int            `json:"severity,omitempty"`
	PluginOutput           string         `json:"plugin_output,omitempty"`
}

type ScansPluginOutputResponse struct {
	Info    *ScansPluginOutputInfo `json:"info,omitempty"`
	Outputs []*PluginOutput        `json:"outputs,omitempty"`
}

func (c *Client) ScansPluginOutput(pathParam *ScansPluginOutputPathParams, query *ScansPluginOutputQuery) (*ScansPluginOutputResponse, error) {
	params := url.Values{}

	if query.HistoryID != 0 {
		params.Add("history_id", fmt.Sprintf("%d", query.HistoryID))
	}

	apiPath := fmt.Sprintf("/scans/%d/plugins/%d", pathParam.ScanID, pathParam.PluginID)
	if pathParam.HostID != 0 {
		apiPath = fmt.Sprintf("/scans/%d/hosts/%d/plugins/%d", pathParam.ScanID, pathParam.HostID, pathParam.PluginID)
	}

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

	var data ScansPluginOutputResponse

	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	return &data, nil
}
