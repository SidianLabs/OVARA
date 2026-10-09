package policy

import (
	"strings"
	"testing"
)

// The gateway evaluates no rule conditions. A rule that claims to be scoped
// by one (as the OPA/Cedar adapters emit: principal_id, agent_id, ...) would
// in fact apply to every request, so it is rejected instead of loaded.
func TestValidator_RejectsConditionsThatWouldSilentlyWiden(t *testing.T) {
	v := NewValidator()
	for _, cond := range []string{
		`{"principal_id": "agent-7"}`,
		`{"agent_id": "agent-7"}`,
		`{"time_window": "09:00-17:00"}`,
		`{"depends_on": "shell:local", "principal_id": "agent-7"}`,
	} {
		data := []byte(`{"version":"v1","rules":[{"action_type":"shell","environment":"local","allow":true,"conditions":` + cond + `}]}`)
		res, err := v.ValidatePolicyData(data)
		if err != nil {
			t.Fatal(err)
		}
		if res.Valid {
			t.Errorf("conditions %s were accepted; the rule would apply to everyone", cond)
			continue
		}
		if !strings.Contains(strings.Join(res.Errors, "\n"), "not evaluated by the gateway") {
			t.Errorf("conditions %s: error does not explain the problem: %v", cond, res.Errors)
		}
	}
}

func TestValidator_StillAcceptsOrderingConditions(t *testing.T) {
	v := NewValidator()
	data := []byte(`{"version":"v1","rules":[
		{"action_type":"shell","environment":"local","allow":true},
		{"action_type":"exec","environment":"local","escalate":true,"conditions":{"depends_on":"shell:local"}}
	]}`)
	res, err := v.ValidatePolicyData(data)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("depends_on is understood and must stay valid: %v", res.Errors)
	}
}

// The same rule must be refused at LOAD time, not just by the validate
// endpoint: ParseStore is what the file loader, hot-reload, candidates and
// distribution all use.
func TestParseStore_RefusesUnevaluatedConditions(t *testing.T) {
	_, err := ParseStore([]byte(`{"version":"v1","rules":[
		{"action_type":"shell","environment":"*","allow":true,"conditions":{"principal_id":"agent-7"}}]}`), "")
	if err == nil || !strings.Contains(err.Error(), "not evaluated") {
		t.Fatalf("a rule with an unevaluated condition must not load, got %v", err)
	}
	if _, err := ParseStore([]byte(`{"version":"v1","rules":[
		{"action_type":"shell","environment":"*","escalate":true,"conditions":{"ref":"exec:*"}}]}`), ""); err != nil {
		t.Fatalf("ref/depends_on are understood and must load: %v", err)
	}
}
