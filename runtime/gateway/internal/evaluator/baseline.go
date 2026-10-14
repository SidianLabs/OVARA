package evaluator

import (
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/policy"
)

// baselineLabel starts the rule name of a decision the organisation's
// baseline made, so a refusal says which layer refused.
const baselineLabel = "org baseline: "

// SetBaseline installs an organisation's policy that the project's policy
// (the store the evaluator was made with) may only narrow. nil removes it.
// It is set before the evaluator serves.
func (e *Evaluator) SetBaseline(s *policy.Store) { e.baseline = s }

// layeredRules is layeredWith for a store's own rule sets.
func (e *Evaluator) layeredRules(store *policy.Store, req *models.ActionRequest) RuleOutcome {
	return e.layeredWith(store, store.RulesForAction(string(req.ActionType)), store.RulesForEnvironment(string(req.Environment)), req)
}

// layeredWith decides with the baseline first and the project's policy
// second, the project only narrowing: a baseline deny is absolute; a
// baseline escalate can become a deny, never an allow; a baseline allow
// stands unless the project has a rule for the request, which then
// decides; where the baseline has no opinion (no rule matched and no
// default deny) the project decides alone. A decision the baseline made
// names its rule as "org baseline: ...".
func (e *Evaluator) layeredWith(store *policy.Store, actionRules, envRules []policy.Rule, req *models.ActionRequest) RuleOutcome {
	p := e.evaluateWithStore(store, actionRules, envRules, req)
	if e.baseline == nil {
		return p
	}
	b := e.evaluateRulesWithStore(e.baseline, req)
	if b.Rule == "" {
		return p
	}
	b.Rule = baselineLabel + b.Rule
	switch {
	case b.Denied:
		return b
	case b.Escalate:
		if p.Denied {
			return p
		}
		return b
	case p.Rule != "":
		return p
	}
	return b
}
