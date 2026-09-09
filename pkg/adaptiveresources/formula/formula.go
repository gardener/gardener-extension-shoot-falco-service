// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package formula

import (
	"crypto/sha256"
	"fmt"
	"math"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"

	apisservice "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
)

// NodeEnv holds node capacity variables available in formula expressions.
type NodeEnv struct {
	NodeCPU         float64
	NodeMemoryMi    float64
	NodeMemoryGi    float64
	NodeEphemeralGi float64
}

// CompiledFormulas holds pre-compiled expr-lang programs for each resource field.
type CompiledFormulas struct {
	CPURequest    *vm.Program
	CPULimit      *vm.Program
	MemoryRequest *vm.Program
	MemoryLimit   *vm.Program
	// ConfigHash is a stable hash of the source ResourceFormulas used for idempotency checks.
	ConfigHash string
}

// Compile parses and type-checks all non-empty expressions in f.
// Returns an error if any expression is invalid.
func Compile(f apisservice.ResourceFormulas) (*CompiledFormulas, error) {
	opts := []expr.Option{
		expr.Env(NodeEnv{}),
		expr.AsFloat64(),
	}

	c := &CompiledFormulas{
		ConfigHash: hashFormulas(f),
	}

	var err error
	if f.CPURequest != nil {
		if c.CPURequest, err = expr.Compile(*f.CPURequest, opts...); err != nil {
			return nil, fmt.Errorf("cpuRequest: %w", err)
		}
	}
	if f.CPULimit != nil {
		if c.CPULimit, err = expr.Compile(*f.CPULimit, opts...); err != nil {
			return nil, fmt.Errorf("cpuLimit: %w", err)
		}
	}
	if f.MemoryRequest != nil {
		if c.MemoryRequest, err = expr.Compile(*f.MemoryRequest, opts...); err != nil {
			return nil, fmt.Errorf("memoryRequest: %w", err)
		}
	}
	if f.MemoryLimit != nil {
		if c.MemoryLimit, err = expr.Compile(*f.MemoryLimit, opts...); err != nil {
			return nil, fmt.Errorf("memoryLimit: %w", err)
		}
	}

	return c, nil
}

// ResourceResult holds the computed resource values for a single DaemonSet.
type ResourceResult struct {
	// CPURequest in millicores string form (e.g. "500m"), empty if not configured.
	CPURequest string
	// CPULimit in millicores string form, empty if not configured.
	CPULimit string
	// MemoryRequest in MiB string form (e.g. "512Mi"), empty if not configured.
	MemoryRequest string
	// MemoryLimit in MiB string form, empty if not configured.
	MemoryLimit string
}

// Eval evaluates all non-nil compiled programs against env and returns a ResourceResult.
func (c *CompiledFormulas) Eval(env NodeEnv) (ResourceResult, error) {
	var result ResourceResult

	if c.CPURequest != nil {
		v, err := runFloat(c.CPURequest, env)
		if err != nil {
			return result, fmt.Errorf("cpuRequest: %w", err)
		}
		result.CPURequest = fmt.Sprintf("%dm", int64(math.Floor(v)))
	}
	if c.CPULimit != nil {
		v, err := runFloat(c.CPULimit, env)
		if err != nil {
			return result, fmt.Errorf("cpuLimit: %w", err)
		}
		result.CPULimit = fmt.Sprintf("%dm", int64(math.Floor(v)))
	}
	if c.MemoryRequest != nil {
		v, err := runFloat(c.MemoryRequest, env)
		if err != nil {
			return result, fmt.Errorf("memoryRequest: %w", err)
		}
		result.MemoryRequest = fmt.Sprintf("%dMi", int64(math.Floor(v)))
	}
	if c.MemoryLimit != nil {
		v, err := runFloat(c.MemoryLimit, env)
		if err != nil {
			return result, fmt.Errorf("memoryLimit: %w", err)
		}
		result.MemoryLimit = fmt.Sprintf("%dMi", int64(math.Floor(v)))
	}

	return result, nil
}

func runFloat(program *vm.Program, env NodeEnv) (float64, error) {
	out, err := expr.Run(program, env)
	if err != nil {
		return 0, err
	}
	v, ok := out.(float64)
	if !ok {
		return 0, fmt.Errorf("expression did not return a number, got %T", out)
	}
	return v, nil
}

func hashFormulas(f apisservice.ResourceFormulas) string {
	h := sha256.New()
	for _, s := range []*string{f.CPURequest, f.CPULimit, f.MemoryRequest, f.MemoryLimit} {
		if s != nil {
			h.Write([]byte(*s))
		}
		h.Write([]byte{0})
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
