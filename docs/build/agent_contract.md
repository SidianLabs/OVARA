# Agent Contract

Every downstream build agent should be given a bounded contract.

## The Agent Must Receive

- the current phase
- exact files or directories to create or modify
- explicit deliverables
- non-goals
- acceptance criteria
- testing requirements
- documentation update requirements

## The Agent Must Not Do

- redefine product scope
- introduce broad new dependencies without justification
- skip tests for new behavior
- leave architecture changes undocumented
- implement future-phase features opportunistically

## Required Output Format

The agent should return:

- what it changed
- files created or modified
- tests added or run
- assumptions made
- open issues or follow-up recommendations

## Review Rule

Any output that silently expands scope should be rejected even if the code is
technically good.

