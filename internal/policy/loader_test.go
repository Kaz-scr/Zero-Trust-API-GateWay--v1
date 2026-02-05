package policy

import (
	"os"
	"testing"
)

func TestValidPolicyLoads(t *testing.T) {
	tmp, err := os.CreateTemp("", "policies*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	data := `
policies:
  - method: GET
    path: /api
    roles: [admin]
`
	if err := os.WriteFile(tmp.Name(), []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	engine := NewEngine()
	err = engine.LoadFromFile(tmp.Name())
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	if len(engine.GetPolicies()) != 1 {
		t.Fatal("expected 1 policy")
	}
}

func TestInvalidPolicyDeniesAll(t *testing.T) {
	tmp, err := os.CreateTemp("", "policies*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	data := `
policies:
  - method: ""
    path: api
    roles: []
`
	if err := os.WriteFile(tmp.Name(), []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	engine := NewEngine()
	err = engine.LoadFromFile(tmp.Name())
	if err == nil {
		t.Fatal("expected validation error")
	}

	if len(engine.GetPolicies()) != 0 {
		t.Fatal("expected deny-all after invalid policy")
	}
}
