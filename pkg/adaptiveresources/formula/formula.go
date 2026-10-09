// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package formula

import (
	"crypto/sha256"
	"fmt"
	"math"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"k8s.io/apimachinery/pkg/api/resource"

	apisservice "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
)

// NodeEnv holds node capacity variables available in formula expressions.
type NodeEnv struct {
	NodeCPU         float64
	NodeMemoryMi    float64
	NodeMemoryGi    float64
	NodeEphemeralGi float64
}

// compiledField holds either a pre-parsed literal quantity string or a compiled expression program.
// Exactly one of literal or program is non-nil/non-empty.
type compiledField struct {
	// literal is the verbatim quantity string when the field was a valid k8s quantity.
	literal string
	// program is the compiled expr-lang program when the field was an expression.
	program *vm.Program
}

// isLiteral reports whether this field holds a plain quantity string.
func (f *compiledField) isLiteral() bool {
	return f.program == nil
}

// CompiledFormulas holds pre-compiled fields for each resource slot.
type CompiledFormulas struct {
	cpuRequest    *compiledField
	cpuLimit      *compiledField
	memoryRequest *compiledField
	memoryLimit   *compiledField
	// ConfigHash is a stable hash of the source FalcoResources used for idempotency checks.
	ConfigHash string
}

// Compile parses all non-nil resource fields in r.
// For each field it first tries resource.ParseQuantity; if that succeeds the literal string
// is stored directly. If parsing fails the field is compiled as an expr-lang expression.
// Returns an error if any expression is syntactically or type-invalid.
func Compile(r *apisservice.FalcoResources) (*CompiledFormulas, error) {
	c := &CompiledFormulas{
		ConfigHash: hashResources(r),
	}

	var err error

	if r == nil {
		return c, nil
	}

	if r.Requests != nil {
		if r.Requests.Cpu != nil {
			if c.cpuRequest, err = compileField(*r.Requests.Cpu, "requests.cpu"); err != nil {
				return nil, err
			}
		}
		if r.Requests.Memory != nil {
			if c.memoryRequest, err = compileField(*r.Requests.Memory, "requests.memory"); err != nil {
				return nil, err
			}
		}
	}

	if r.Limits != nil {
		if r.Limits.Cpu != nil {
			if c.cpuLimit, err = compileField(*r.Limits.Cpu, "limits.cpu"); err != nil {
				return nil, err
			}
		}
		if r.Limits.Memory != nil {
			if c.memoryLimit, err = compileField(*r.Limits.Memory, "limits.memory"); err != nil {
				return nil, err
			}
		}
	}

	return c, nil
}

func compileField(s, fieldName string) (*compiledField, error) {
	// Try as a k8s quantity first.
	if _, err := resource.ParseQuantity(s); err == nil {
		return &compiledField{literal: s}, nil
	}
	// Fall back to expression compilation.
	opts := []expr.Option{
		expr.Env(NodeEnv{}),
		expr.AsFloat64(),
	}
	prog, err := expr.Compile(s, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fieldName, err)
	}
	return &compiledField{program: prog}, nil
}

// ResourceResult holds the computed resource values for a single DaemonSet.
type ResourceResult struct {
	// CPURequest in millicores string form (e.g. "500m"), or literal quantity, empty if not configured.
	CPURequest string
	// CPULimit in millicores string form or literal quantity, empty if not configured.
	CPULimit string
	// MemoryRequest in MiB string form (e.g. "512Mi") or literal quantity, empty if not configured.
	MemoryRequest string
	// MemoryLimit in MiB string form or literal quantity, empty if not configured.
	MemoryLimit string
}

// Eval evaluates all non-nil compiled fields against env and returns a ResourceResult.
// For literal fields the stored quantity string is returned verbatim.
// For expression fields the program is evaluated and formatted as millicores (CPU) or MiB (memory).
func (c *CompiledFormulas) Eval(env NodeEnv) (ResourceResult, error) {
	var result ResourceResult
	var err error

	if c.cpuRequest != nil {
		if result.CPURequest, err = evalCPUField(c.cpuRequest, env, "requests.cpu"); err != nil {
			return result, err
		}
	}
	if c.cpuLimit != nil {
		if result.CPULimit, err = evalCPUField(c.cpuLimit, env, "limits.cpu"); err != nil {
			return result, err
		}
	}
	if c.memoryRequest != nil {
		if result.MemoryRequest, err = evalMemoryField(c.memoryRequest, env, "requests.memory"); err != nil {
			return result, err
		}
	}
	if c.memoryLimit != nil {
		if result.MemoryLimit, err = evalMemoryField(c.memoryLimit, env, "limits.memory"); err != nil {
			return result, err
		}
	}

	return result, nil
}

func evalCPUField(f *compiledField, env NodeEnv, fieldName string) (string, error) {
	if f.isLiteral() {
		return f.literal, nil
	}
	v, err := runFloat(f.program, env)
	if err != nil {
		return "", fmt.Errorf("%s: %w", fieldName, err)
	}
	return fmt.Sprintf("%dm", int64(math.Floor(v))), nil
}

func evalMemoryField(f *compiledField, env NodeEnv, fieldName string) (string, error) {
	if f.isLiteral() {
		return f.literal, nil
	}
	v, err := runFloat(f.program, env)
	if err != nil {
		return "", fmt.Errorf("%s: %w", fieldName, err)
	}
	return fmt.Sprintf("%dMi", int64(math.Floor(v))), nil
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

func hashResources(r *apisservice.FalcoResources) string {
	h := sha256.New()
	if r == nil {
		return fmt.Sprintf("%x", h.Sum(nil))
	}
	writeOptional := func(s *string) {
		if s != nil {
			h.Write([]byte(*s))
		}
		h.Write([]byte{0})
	}
	if r.Requests != nil {
		writeOptional(r.Requests.Cpu)
		writeOptional(r.Requests.Memory)
	} else {
		writeOptional(nil)
		writeOptional(nil)
	}
	if r.Limits != nil {
		writeOptional(r.Limits.Cpu)
		writeOptional(r.Limits.Memory)
	} else {
		writeOptional(nil)
		writeOptional(nil)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
