# Category Definition

Ovara defines the category of autonomous runtime trust infrastructure.

This category is the control layer that sits between autonomous systems and the
systems they can change.

It combines ideas from IAM, policy systems, observability, workload identity,
runtime security, and approval infrastructure, but it is not reducible to any
one of them. The defining property is that decisions are made at execution time
for probabilistic machine actors operating under delegated authority.

## What The Category Does

- intercepts machine actions before side effects occur
- verifies the machine actor and its delegated authority
- evaluates policy using identity, context, and trust state
- escalates high-risk actions to human approval when required
- emits a portable execution receipt after the decision

## What The Category Is Not

- chatbot tooling
- workflow glue
- model monitoring alone
- traditional application security
- a compliance reporting layer
- generic prompt governance

## Why Existing Categories Fall Short

- IAM authenticates principals, but does not govern each adaptive machine action
- observability records events, but does not decide whether they should occur
- policy systems often assume static apps and human operators
- endpoint and cloud security do not model delegated reasoning-driven execution

## Category Test

If a product cannot answer "should this machine action happen right now, under
this authority, in this environment, and with this trust state?" it is adjacent
to this category, but not the category itself.
