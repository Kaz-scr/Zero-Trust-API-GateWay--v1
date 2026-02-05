package policy

import (
	"errors"
	"fmt"
	"strings"
)

/*
Validation rules are intentionally strict.
Loose validation is a security risk.
*/

func validatePolicyFile(pf PolicyFile) error {
	if len(pf.Policies) == 0 {
		return errors.New("policy file contains no policies")
	}

	for i, p := range pf.Policies {
		if strings.TrimSpace(p.Method) == "" {
			return policyError(i, "method is required")
		}

		if strings.TrimSpace(p.Path) == "" {
			return policyError(i, "path is required")
		}

		if !strings.HasPrefix(p.Path, "/") {
			return policyError(i, "path must start with '/'")
		}

		if len(p.Roles) == 0 {
			return policyError(i, "roles must not be empty")
		}

		for _, r := range p.Roles {
			if strings.TrimSpace(r) == "" {
				return policyError(i, "role names must not be empty")
			}
		}
	}

	return nil
}

func policyError(index int, msg string) error {
	return errors.New("policy[" + itoa(index) + "]: " + msg)
}

// tiny helper to avoid strconv import
func itoa(i int) string {
	return fmt.Sprintf("%d", i)
}
