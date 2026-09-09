// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"testing"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
)

func TestValidateCPUQuantity(t *testing.T) {
	tests := []struct {
		name        string
		cpu         string
		expectError bool
	}{
		{"valid millicores", "100m", false},
		{"valid cores", "1", false},
		{"valid decimal cores", "0.5", false},
		{"zero CPU", "0", true},
		{"negative CPU", "-100m", true},
		{"too large CPU", "2000", true},
		{"invalid format", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCPUQuantity(tt.cpu)
			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("expected no error but got: %v", err)
			}
		})
	}
}

func TestValidateMemoryQuantity(t *testing.T) {
	tests := []struct {
		name        string
		memory      string
		expectError bool
	}{
		{"valid Mi", "128Mi", false},
		{"valid Gi", "1Gi", false},
		{"valid bytes", "134217728", false},
		{"zero memory", "0", true},
		{"too small memory", "100Ki", true},
		{"too large memory", "2Ti", true},
		{"negative memory", "-128Mi", true},
		{"invalid format", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMemoryQuantity(tt.memory)
			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("expected no error but got: %v", err)
			}
		})
	}
}

func TestValidateRequestNotGreaterThanLimit(t *testing.T) {
	tests := []struct {
		name        string
		request     string
		limit       string
		expectError bool
	}{
		{"request less than limit (same unit)", "100m", "200m", false},
		{"request equal to limit", "100m", "100m", false},
		{"request less than limit (different units)", "0.5", "1000m", false},
		{"memory request less than limit (different units)", "512Mi", "1Gi", false},
		{"request greater than limit (same unit)", "200m", "100m", true},
		{"request greater than limit (different units)", "2", "1000m", true},
		{"memory request greater than limit (different units)", "2Gi", "1024Mi", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRequestNotGreaterThanLimit(tt.request, tt.limit)
			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("expected no error but got: %v", err)
			}
		})
	}
}

func TestVerifyFalcoConfigResources(t *testing.T) {
	tests := []struct {
		name        string
		config      *service.FalcoServiceConfig
		expectError bool
	}{
		{
			name: "valid resources",
			config: &service.FalcoServiceConfig{
				FalcoConfig: &service.FalcoConfig{
					Resources: &service.FalcoResources{
						Requests: &service.ResourceValues{
							Cpu:    stringPtr("100m"),
							Memory: stringPtr("128Mi"),
						},
						Limits: &service.ResourceValues{
							Cpu:    stringPtr("200m"),
							Memory: stringPtr("256Mi"),
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid resources with different units",
			config: &service.FalcoServiceConfig{
				FalcoConfig: &service.FalcoConfig{
					Resources: &service.FalcoResources{
						Requests: &service.ResourceValues{
							Cpu:    stringPtr("0.5"),
							Memory: stringPtr("512Mi"),
						},
						Limits: &service.ResourceValues{
							Cpu:    stringPtr("1000m"),
							Memory: stringPtr("1Gi"),
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "CPU request greater than limit",
			config: &service.FalcoServiceConfig{
				FalcoConfig: &service.FalcoConfig{
					Resources: &service.FalcoResources{
						Requests: &service.ResourceValues{
							Cpu: stringPtr("2"),
						},
						Limits: &service.ResourceValues{
							Cpu: stringPtr("1"),
						},
					},
				},
			},
			expectError: true,
		},
		{
			name: "memory request greater than limit (different units)",
			config: &service.FalcoServiceConfig{
				FalcoConfig: &service.FalcoConfig{
					Resources: &service.FalcoResources{
						Requests: &service.ResourceValues{
							Memory: stringPtr("2Gi"),
						},
						Limits: &service.ResourceValues{
							Memory: stringPtr("1024Mi"),
						},
					},
				},
			},
			expectError: true,
		},
		{
			name: "invalid CPU value",
			config: &service.FalcoServiceConfig{
				FalcoConfig: &service.FalcoConfig{
					Resources: &service.FalcoResources{
						Requests: &service.ResourceValues{
							Cpu: stringPtr("0"),
						},
					},
				},
			},
			expectError: true,
		},
		{
			name: "invalid memory value",
			config: &service.FalcoServiceConfig{
				FalcoConfig: &service.FalcoConfig{
					Resources: &service.FalcoResources{
						Requests: &service.ResourceValues{
							Memory: stringPtr("100Ki"),
						},
					},
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyFalcoConfigResources(tt.config)
			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("expected no error but got: %v", err)
			}
		})
	}
}

func TestVerifyFalcoConfigResourcesWorkerPoolOverrides(t *testing.T) {
	tests := []struct {
		name        string
		config      *service.FalcoServiceConfig
		expectError bool
		errContains string
	}{
		{
			name: "valid per-pool override",
			config: &service.FalcoServiceConfig{
				FalcoConfig: &service.FalcoConfig{
					Resources: &service.FalcoResources{
						Requests: &service.ResourceValues{Cpu: stringPtr("100m")},
					},
					WorkerPoolResources: map[string]*service.FalcoResources{
						"pool-a": {
							Requests: &service.ResourceValues{Cpu: stringPtr("200m"), Memory: stringPtr("256Mi")},
							Limits:   &service.ResourceValues{Cpu: stringPtr("400m"), Memory: stringPtr("512Mi")},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "invalid CPU in per-pool override",
			config: &service.FalcoServiceConfig{
				FalcoConfig: &service.FalcoConfig{
					WorkerPoolResources: map[string]*service.FalcoResources{
						"pool-a": {
							Requests: &service.ResourceValues{Cpu: stringPtr("0")},
						},
					},
				},
			},
			expectError: true,
			errContains: "workerPoolResources[pool-a]",
		},
		{
			name: "per-pool CPU request greater than limit",
			config: &service.FalcoServiceConfig{
				FalcoConfig: &service.FalcoConfig{
					WorkerPoolResources: map[string]*service.FalcoResources{
						"pool-b": {
							Requests: &service.ResourceValues{Cpu: stringPtr("800m")},
							Limits:   &service.ResourceValues{Cpu: stringPtr("400m")},
						},
					},
				},
			},
			expectError: true,
			errContains: "workerPoolResources[pool-b]",
		},
		{
			name: "nil per-pool entry is skipped",
			config: &service.FalcoServiceConfig{
				FalcoConfig: &service.FalcoConfig{
					WorkerPoolResources: map[string]*service.FalcoResources{
						"pool-a": nil,
					},
				},
			},
			expectError: false,
		},
		{
			name: "invalid expression (unknown variable) is rejected",
			config: &service.FalcoServiceConfig{
				FalcoConfig: &service.FalcoConfig{
					Resources: &service.FalcoResources{
						Requests: &service.ResourceValues{Cpu: stringPtr("NodeGPU * 4")},
					},
				},
			},
			expectError: true,
		},
		{
			name: "expression in CPU is accepted (valid expr-lang expression)",
			config: &service.FalcoServiceConfig{
				FalcoConfig: &service.FalcoConfig{
					Resources: &service.FalcoResources{
						Requests: &service.ResourceValues{Cpu: stringPtr("NodeCPU < 4 ? 400.0 : 800.0")},
					},
				},
			},
			expectError: false,
		},
		{
			name: "expression in memory is accepted",
			config: &service.FalcoServiceConfig{
				FalcoConfig: &service.FalcoConfig{
					Resources: &service.FalcoResources{
						Requests: &service.ResourceValues{Memory: stringPtr("NodeMemoryGi * 32.0")},
					},
				},
			},
			expectError: false,
		},
		{
			name: "expression in per-pool override is accepted",
			config: &service.FalcoServiceConfig{
				FalcoConfig: &service.FalcoConfig{
					WorkerPoolResources: map[string]*service.FalcoResources{
						"pool-a": {
							Requests: &service.ResourceValues{
								Cpu:    stringPtr("NodeMemoryGi < 10 ? 200 : 400"),
								Memory: stringPtr("NodeMemoryGi * 8"),
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name:        "nil FalcoConfig is accepted",
			config:      &service.FalcoServiceConfig{FalcoConfig: nil},
			expectError: false,
		},
		{
			name:        "nil FalcoServiceConfig is accepted",
			config:      nil,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyFalcoConfigResources(tt.config)
			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("expected no error but got: %v", err)
			}
			if tt.expectError && tt.errContains != "" && err != nil {
				if !contains(err.Error(), tt.errContains) {
					t.Errorf("expected error to contain %q, got: %v", tt.errContains, err)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}

func stringPtr(s string) *string {
	return &s
}
