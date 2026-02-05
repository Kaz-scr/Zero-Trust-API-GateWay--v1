package policy

import (
	"fmt"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

/*
SECURITY DESIGN:

- Policies are static data, not code
- No expressions, no templates, no interpolation
- Validation happens BEFORE policies are accepted
- Any error results in DENY-ALL behavior
*/

type Rule struct {
	Method string   `yaml:"method"`
	Path   string   `yaml:"path"`
	Roles  []string `yaml:"roles"`
}

type PolicyFile struct {
	Policies []Rule `yaml:"policies"`
}

// Engine holds the active policy set.
// Access is guarded by RWMutex for hot reloads.
type Engine struct {
	mu       sync.RWMutex
	policies []Rule
	loaded   bool
}

// NewEngine creates an empty policy engine.
// Empty engine == deny all.
func NewEngine() *Engine {
	return &Engine{}
}

// GetPolicies returns a snapshot of current policies.
// If not loaded or invalid, returns empty slice (deny all).
func (e *Engine) GetPolicies() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.loaded {
		return nil
	}

	return e.policies
}

// LoadFromFile loads and validates policies from disk.
func (e *Engine) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		e.invalidate()
		return fmt.Errorf("failed to read policy file: %w", err)
	}

	var pf PolicyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		e.invalidate()
		return fmt.Errorf("invalid YAML: %w", err)
	}

	if err := validatePolicyFile(pf); err != nil {
		e.invalidate()
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.policies = pf.Policies
	e.loaded = true
	return nil
}

// Watch watches the policy file for changes and reloads it.
// On ANY error → policies are invalidated (deny all).
func (e *Engine) Watch(path string, interval time.Duration) {
	go func() {
		var lastMod time.Time

		for {
			info, err := os.Stat(path)
			if err != nil {
				e.invalidate()
				time.Sleep(interval)
				continue
			}

			if info.ModTime().After(lastMod) {
				if err := e.LoadFromFile(path); err != nil {
					// Error already invalidated policies
				} else {
					lastMod = info.ModTime()
				}
			}

			time.Sleep(interval)
		}
	}()
}

func (e *Engine) invalidate() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.policies = nil
	e.loaded = false
}
