# China Financial GRC Product Review Questions

Use these when a feature request is too vague to choose a product slice. Ask no
more than three questions at a time, and answer from repository evidence before
asking the user.

## First questions

1. Which user and accountable reviewer owns the decision: regulatory analyst,
   legal/compliance, risk, privacy, security, control owner, audit, finance, or
   management?
2. What observable decision or workflow should become faster, safer, or more
   consistent?
3. What is the most costly failure: missed obligation, false applicability,
   stale policy, weak evidence, authority bypass, customer harm, or audit
   independence failure?

## Scope questions

- Which legal entities, licences, jurisdictions, products, customers, data, and
  systems are in scope?
- Is this external regulation, an internal policy, or a mapping between them?
- Which official source versions and applicability facts are required?
- Is one entity and a small reviewed source set sufficient for the first slice?
- What must remain explicitly out of scope?

## Workflow and authority questions

- What happens today from trigger to evidence and final sign-off?
- Which steps are deterministic, model-assisted, or human-only?
- Who may propose, review, approve, execute, revoke, and independently audit?
- Can the first version be read-only or proposal-based?
- What exact diff, citation, and audit record must a reviewer see?

## Data and integration questions

- What private or regulated data is required, and where may it be processed?
- Does the feature depend on a licensed source, private internal policy,
  enterprise-edition capability, or external connector?
- What happens when a source, model, vector store, or connector is unavailable?
- How are retry, duplicate, rollback, retention, and deletion handled?

## Measurement questions

- What baseline exists today?
- Which quality, safety, timeliness, adoption, and cost metric proves value?
- How many human-reviewed examples are enough for a pilot decision?
- What threshold blocks release or triggers rollback?

## Cutline questions

- What is the smallest end-to-end result a user can review and accept?
- Which UI polish, domains, connectors, and autonomous actions can wait?
- What evidence would justify moving the feature to the next roadmap phase?
