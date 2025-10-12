package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type ScanSettings struct {
	PatchAuditOverTelnet            string `json:"patch_audit_over_telnet,omitempty"`
	PatchAuditOverRsh               string `json:"patch_audit_over_rsh,omitempty"`
	PatchAuditOverRexec             string `json:"patch_audit_over_rexec,omitempty"`
	SnmpPort                        string `json:"snmp_port,omitempty"`
	AdditionalSnmpPort1             string `json:"additional_snmp_port1,omitempty"`
	AdditionalSnmpPort2             string `json:"additional_snmp_port2,omitempty"`
	AdditionalSnmpPort3             string `json:"additional_snmp_port3,omitempty"`
	HTTPLoginMethod                 string `json:"http_login_method,omitempty"`
	HTTPReauthDelay                 string `json:"http_reauth_delay,omitempty"`
	HTTPLoginMaxRedir               string `json:"http_login_max_redir,omitempty"`
	HTTPLoginInvertAuthRegex        string `json:"http_login_invert_auth_regex,omitempty"`
	HTTPLoginAuthRegexOnHeaders     string `json:"http_login_auth_regex_on_headers,omitempty"`
	HTTPLoginAuthRegexNocase        string `json:"http_login_auth_regex_nocase,omitempty"`
	NeverSendWinCredsInTheClear     string `json:"never_send_win_creds_in_the_clear,omitempty"`
	DontUseNtlmv1                   string `json:"dont_use_ntlmv1,omitempty"`
	StartRemoteRegistry             string `json:"start_remote_registry,omitempty"`
	EnableAdminShares               string `json:"enable_admin_shares,omitempty"`
	StartServerService              string `json:"start_server_service,omitempty"`
	SSHKnownHosts                   string `json:"ssh_known_hosts,omitempty"`
	SSHPort                         string `json:"ssh_port,omitempty"`
	SSHClientBanner                 string `json:"ssh_client_banner,omitempty"`
	AttemptLeastPrivilege           string `json:"attempt_least_privilege,omitempty"`
	LogWholeAttack                  string `json:"log_whole_attack,omitempty"`
	AlwaysReportSSHCmds             string `json:"always_report_ssh_cmds,omitempty"`
	EnablePluginDebugging           string `json:"enable_plugin_debugging,omitempty"`
	DebugLevel                      string `json:"debug_level,omitempty"`
	EnablePluginList                string `json:"enable_plugin_list,omitempty"`
	AuditTrail                      string `json:"audit_trail,omitempty"`
	IncludeKb                       string `json:"include_kb,omitempty"`
	WindowsSearchFilepathExclusions string `json:"windows_search_filepath_exclusions,omitempty"`
	WindowsSearchFilepathInclusions string `json:"windows_search_filepath_inclusions,omitempty"`
	CustomFindFilepathExclusions    string `json:"custom_find_filepath_exclusions,omitempty"`
	CustomFindFilesystemExclusions  string `json:"custom_find_filesystem_exclusions,omitempty"`
	CustomFindFilepathInclusions    string `json:"custom_find_filepath_inclusions,omitempty"`
	ReduceConnectionsOnCongestion   string `json:"reduce_connections_on_congestion,omitempty"`
	NetworkReceiveTimeout           string `json:"network_receive_timeout,omitempty"`
	MaxChecksPerHost                string `json:"max_checks_per_host,omitempty"`
	MaxHostsPerScan                 string `json:"max_hosts_per_scan,omitempty"`
	MaxSimultTCPSessionsPerHost     string `json:"max_simult_tcp_sessions_per_host,omitempty"`
	MaxSimultTCPSessionsPerScan     string `json:"max_simult_tcp_sessions_per_scan,omitempty"`
	SafeChecks                      string `json:"safe_checks,omitempty"`
	VendorUnpatched                 string `json:"vendor_unpatched,omitempty"`
	StopScanOnDisconnect            string `json:"stop_scan_on_disconnect,omitempty"`
	SliceNetworkAddresses           string `json:"slice_network_addresses,omitempty"`
	AutoAcceptDisclaimer            string `json:"auto_accept_disclaimer,omitempty"`
	ScanAllowMultiTarget            string `json:"scan.allow_multi_target,omitempty"`
	HostTagging                     string `json:"host_tagging,omitempty"`
	TrustedCas                      string `json:"trusted_cas,omitempty"`
	AdvancedMode                    string `json:"advanced_mode,omitempty"`
	AllowPostScanEditing            string `json:"allow_post_scan_editing,omitempty"`
	ReverseLookup                   string `json:"reverse_lookup,omitempty"`
	LogLiveHosts                    string `json:"log_live_hosts,omitempty"`
	DisplayUnreachableHosts         string `json:"display_unreachable_hosts,omitempty"`
	DisplayUnicodeCharacters        string `json:"display_unicode_characters,omitempty"`
	ReportVerbosity                 string `json:"report_verbosity,omitempty"`
	ReportSupersededPatches         string `json:"report_superseded_patches,omitempty"`
	SilentDependencies              string `json:"silent_dependencies,omitempty"`
	OracleDatabaseUseDetectedSids   string `json:"oracle_database_use_detected_sids,omitempty"`
	SamrEnumeration                 string `json:"samr_enumeration,omitempty"`
	AdsiQuery                       string `json:"adsi_query,omitempty"`
	WmiQuery                        string `json:"wmi_query,omitempty"`
	RidBruteForcing                 string `json:"rid_brute_forcing,omitempty"`
	RequestWindowsDomainInfo        string `json:"request_windows_domain_info,omitempty"`
	ScanWebapps                     string `json:"scan_webapps,omitempty"`
	UserAgentString                 string `json:"user_agent_string,omitempty"`
	TestDefaultOracleAccounts       string `json:"test_default_oracle_accounts,omitempty"`
	ProvidedCredsOnly               string `json:"provided_creds_only,omitempty"`
	ReportParanoia                  string `json:"report_paranoia,omitempty"`
	ThoroughTests                   string `json:"thorough_tests,omitempty"`
	AssessmentMode                  string `json:"assessment_mode,omitempty"`
	CollectIdentityDataFromAd       string `json:"collect_identity_data_from_ad,omitempty"`
	SvcDetectionOnAllPorts          string `json:"svc_detection_on_all_ports,omitempty"`
	DetectSsl                       string `json:"detect_ssl,omitempty"`
	SslProbPorts                    string `json:"ssl_prob_ports,omitempty"`
	DtlsProbPorts                   string `json:"dtls_prob_ports,omitempty"`
	CertExpiryWarningDays           string `json:"cert_expiry_warning_days,omitempty"`
	EnumerateAllCiphers             string `json:"enumerate_all_ciphers,omitempty"`
	CheckCrl                        string `json:"check_crl,omitempty"`
	TCPScanner                      string `json:"tcp_scanner,omitempty"`
	TCPFirewallDetection            string `json:"tcp_firewall_detection,omitempty"`
	SynScanner                      string `json:"syn_scanner,omitempty"`
	SynFirewallDetection            string `json:"syn_firewall_detection,omitempty"`
	UDPScanner                      string `json:"udp_scanner,omitempty"`
	SSHNetstatScanner               string `json:"ssh_netstat_scanner,omitempty"`
	WmiNetstatScanner               string `json:"wmi_netstat_scanner,omitempty"`
	SnmpScanner                     string `json:"snmp_scanner,omitempty"`
	OnlyPortscanIfEnumFailed        string `json:"only_portscan_if_enum_failed,omitempty"`
	VerifyOpenPorts                 string `json:"verify_open_ports,omitempty"`
	UnscannedClosed                 string `json:"unscanned_closed,omitempty"`
	PortscanRange                   string `json:"portscan_range,omitempty"`
	WolMacAddresses                 string `json:"wol_mac_addresses,omitempty"`
	WolWaitTime                     string `json:"wol_wait_time,omitempty"`
	ScanNetworkPrinters             string `json:"scan_network_printers,omitempty"`
	ScanNetwareHosts                string `json:"scan_netware_hosts,omitempty"`
	ScanOtDevices                   string `json:"scan_ot_devices,omitempty"`
	PingTheRemoteHost               string `json:"ping_the_remote_host,omitempty"`
	ArpPing                         string `json:"arp_ping,omitempty"`
	TCPPing                         string `json:"tcp_ping,omitempty"`
	TCPPingDestPorts                string `json:"tcp_ping_dest_ports,omitempty"`
	IcmpPing                        string `json:"icmp_ping,omitempty"`
	IcmpUnreachMeansHostDown        string `json:"icmp_unreach_means_host_down,omitempty"`
	IcmpPingRetries                 string `json:"icmp_ping_retries,omitempty"`
	UDPPing                         string `json:"udp_ping,omitempty"`
	TestLocalNessusHost             string `json:"test_local_nessus_host,omitempty"`
	FastNetworkDiscovery            string `json:"fast_network_discovery,omitempty"`
	DiscoveryMode                   string `json:"discovery_mode,omitempty"`
	Emails                          string `json:"emails,omitempty"`
	FilterType                      string `json:"filter_type,omitempty"`
	Filters                         any    `json:"filters,omitempty"`
	LaunchNow                       bool   `json:"launch_now,omitempty"`
	Enabled                         bool   `json:"enabled,omitempty"`
	Name                            string `json:"name,omitempty"`
	Description                     string `json:"description,omitempty"`
	FolderID                        int    `json:"folder_id,omitempty"`
	ScannerID                       string `json:"scanner_id,omitempty"`
	TextTargets                     string `json:"text_targets,omitempty"`
	FileTargets                     string `json:"file_targets,omitempty"`
}

type ScansCreateCustomRequest struct {
	TemplateUUID TemplateType  `json:"uuid,omitempty"`
	Settings     *ScanSettings `json:"settings,omitempty"`
}

func (c *Client) ScansCreateCustom(request *ScansCreateCustomRequest) (*ScansCreateResponse, error) {
	reqBody, err := sonic.Marshal(request)
	if err != nil {
		return nil, err
	}

	resp, err := c.Post(c.getAPIURL("/scans"), "application/json", reqBody)
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

	var data ScansCreateResponse
	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return &data, nil
}
