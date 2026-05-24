# Build System

This directory defines how Ovara should be built through an iterative
agent-driven execution model.

The intended loop is:

1. define the current phase and bounded objective
2. issue a focused implementation prompt to a build agent
3. review the agent output against architecture, security, and scope
4. issue a correction or next-step prompt
5. repeat until the phase exit criteria are met

Core documents:

- [program_plan.md](/Volumes/Portable%20Mac/ovara/docs/build/program_plan.md)
- [phase_plan.md](/Volumes/Portable%20Mac/ovara/docs/build/phase_plan.md)
- [agent_contract.md](/Volumes/Portable%20Mac/ovara/docs/build/agent_contract.md)
- [review_loop.md](/Volumes/Portable%20Mac/ovara/docs/build/review_loop.md)
- [prompt_templates.md](/Volumes/Portable%20Mac/ovara/docs/build/prompt_templates.md)
- [acceptance_checklists.md](/Volumes/Portable%20Mac/ovara/docs/build/acceptance_checklists.md)

