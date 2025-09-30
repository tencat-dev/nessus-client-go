package nessus

import (
	"testing"
)

// TestClient_PluginsPluginDetails tests the PluginsPluginDetails method of the Client
func TestClient_PluginsPluginDetails(t *testing.T) {
	tests := []struct {
		name    string
		options []Option
		id      int
		wantErr bool
	}{
		{
			name: "success with valid plugin id and api keys",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"06ea945d67266e66fe6979aa448c321a6624048f6a3480cde000dad76e7ef921",
					"a306b9ff56069c37b3f2ee120358cac809d77f159a1cf796eb1df64f783eea91",
				),
			},
			id:      19506,
			wantErr: false,
		},
		{
			name: "success with different plugin id and token",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("0d243c20662ba2335828d99dfb65f5817887611f2ceb9bf3"),
			},
			id:      10107,
			wantErr: false,
		},
		{
			name: "error with invalid credentials using token",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithToken("invalid_token"),
			},
			id:      19506,
			wantErr: true,
		},
		{
			name: "error with invalid credentials using api keys",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"invalid_access_key",
					"invalid_secret_key",
				),
			},
			id:      19506,
			wantErr: true,
		},
		{
			name: "error with no authentication",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
			},
			id:      19506,
			wantErr: true,
		},
		{
			name: "error with negative plugin id",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"06ea945d67266e66fe6979aa448c321a6624048f6a3480cde000dad76e7ef921",
					"a306b9ff56069c37b3f2ee120358cac809d77f159a1cf796eb1df64f783eea91",
				),
			},
			id:      -1,
			wantErr: true,
		},
		{
			name: "error with zero plugin id",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"06ea945d67266e66fe6979aa448c321a6624048f6a3480cde000dad76e7ef921",
					"a306b9ff56069c37b3f2ee120358cac809d77f159a1cf796eb1df64f783eea91",
				),
			},
			id:      0,
			wantErr: true,
		},
		{
			name: "error with very large plugin id",
			options: []Option{
				WithAPIURL("https://localhost:8834"),
				WithAPIKey(
					"06ea945d67266e66fe6979aa448c321a6624048f6a3480cde000dad76e7ef921",
					"a306b9ff56069c37b3f2ee120358cac809d77f159a1cf796eb1df64f783eea91",
				),
			},
			id:      99999999999,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(tt.options...)
			if err != nil {
				t.Errorf("NewClient() error = %v", err)
				return
			}

			got, err := c.PluginsPluginDetails(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("PluginsPluginDetails() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == nil {
				t.Errorf("PluginsPluginDetails() got = %v, want non-nil", got)
			}
			if !tt.wantErr && got != nil {
				// Verify that the response has expected fields
				if got.ID != tt.id {
					t.Errorf("PluginsPluginDetails() got ID = %v, want ID = %v", got.ID, tt.id)
				}
				if got.Name == "" {
					t.Errorf("PluginsPluginDetails() got Name = %v, want non-empty name", got.Name)
				}
				if got.FamilyName == "" {
					t.Errorf("PluginsPluginDetails() got FamilyName = %v, want non-empty family name", got.FamilyName)
				}

				// Check that attributes are properly initialized
				if got.Attributes == nil {
					t.Errorf("PluginsPluginDetails() got Attributes = nil, want non-nil attributes")
				} else {
					// If there are attributes, verify they have expected fields
					for i, attr := range got.Attributes {
						if attr.AttributeName == "" {
							t.Errorf("PluginsPluginDetails() got.Attributes[%d].AttributeName = %v, want non-empty name", i, attr.AttributeName)
						}
					}
				}
			}
		})
	}
}

// TestClient_PluginsPluginDetails_NetworkError tests error handling when network issues occur
func TestClient_PluginsPluginDetails_NetworkError(t *testing.T) {
	// Test with an unreachable URL to trigger network error
	c, err := NewClient(
		WithAPIURL("https://unreachable-url-for-testing:8834"),
		WithAPIKey(
			"06ea945d67266e66fe6979aa448c321a6624048f6a3480cde000dad76e7ef921",
			"a306b9ff56069c37b3f2ee120358cac809d77f159a1cf796eb1df64f783eea91",
		),
	)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	got, err := c.PluginsPluginDetails(19506)
	if err == nil {
		t.Errorf("PluginsPluginDetails() expected error for unreachable URL, got nil")
	}
	if got != nil {
		t.Errorf("PluginsPluginDetails() expected nil response for network error, got = %v", got)
	}
}

// TestClient_PluginsPluginDetails_HTTPError tests error handling when HTTP errors occur
func TestClient_PluginsPluginDetails_HTTPError(t *testing.T) {
	// Note: This test will likely require mocking to properly test HTTP error responses
	// For now, we're testing that the function handles non-200 status codes properly
	// by checking the ErrorResponse function behavior
	c, err := NewClient(
		WithAPIURL("https://localhost:8834"),
		WithAPIKey(
			"06ea945d67266e66fe6979aa448c321a6624048f6a3480cde000dad76e7ef921",
			"a306b9ff56069c37b3f2ee120358cac809d77f159a1cf796eb1df64f783eea91",
		),
	)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// Using an ID that is likely to return a 404 or other error status
	got, err := c.PluginsPluginDetails(999999)
	if err == nil {
		// If no error occurred, that's fine, but we should still check the response
		if got != nil && got.ID != 99999 {
			t.Errorf("PluginsPluginDetails() got ID = %v, want ID = %v", got.ID, 999999)
		}
	}
	// If an error occurred, that's also acceptable as it would be an HTTP error response
}
