# V0.7 provider setup

Register only trusted target definitions through `OPSPILOT_INVENTORY_FILE`. The file
is a JSON array with `host_id`, `provider` and `spec`. Every spec requires `tenant_id`,
`environment` (`production` or `nonproduction`), `package`, and `target_version`.
Optional `maintenance_window` defaults false and `vulnerabilities` defaults empty.
Use the incident CVE as a matching vulnerability entry if you need risk evidence.
Credentials belong in the SDK credential chain or mounted secrets, never inventory.
The registered tenant is checked before remote reads; Kubernetes/EC2 additionally
check the actual ownership label/tag. Remote targets are explicitly administrative
bindings; Terraform and GitHub need project/repository permissions enforcing tenancy.

## Kubernetes

```json
[{"host_id":"kube-api","provider":"kubernetes","spec":{
  "tenant_id":"platform-sre","environment":"production",
  "package":"container-image","target_version":"registry.example/api@sha256:2222222222222222222222222222222222222222222222222222222222222222",
  "namespace":"apps","deployment":"api","container":"api","verification_timeout":60
}}]
```

Use in-cluster service-account credentials or your kubeconfig. The Deployment needs
`opspilot.io/tenant: platform-sre`. Grant read/patch of the specific Deployment;
no arbitrary resource creation is implemented. Only the configured container image
changes, guarded by resourceVersion and image tests. Verification requires observed
generation and all desired replicas updated/available. Recovery can prove a patch by
its atomic run annotation plus image. Rollback restores the previous pinned image
only if the image and run annotation still match; acknowledgement means the desired
image was restored, not that rollback rollout health was reverified.

## AWS EC2 / SSM

```json
[{"host_id":"aws-api","provider":"aws","spec":{
  "tenant_id":"platform-sre","environment":"production","package":"openssl",
  "target_version":"3.1.4","instance_id":"i-0123456789abcdef0","region":"us-east-1",
  "patch_document":"OpsPilot-PatchPackage","rollback_document":"OpsPilot-RollbackPackage",
  "command_timeout":60
}}]
```

Use the standard boto3 credential chain/workload role. The instance must have an
`opspilot:tenant` tag and SSM `AWS:Application` inventory containing exactly one
matching package. Provision narrow, reviewed `OpsPilot-*` SSM documents accepting
`Package` and `Version` string-list parameters; IAM must constrain the document and
instance. The prefix is a naming restriction, not document-content validation.
The repository does not provision your documents or allow arbitrary shell text.
Grant EC2 instance/health reads, SSM inventory reads, send-command and command-status
reads for the configured targets. A known command ID is reconciled without resend.
A lost submission response with no saved command ID stays blocked. SSM inventory may
lag a patch; a false postcheck triggers the configured rollback document. Validate
inventory update timing and document behavior in staging.

## Terraform

```json
[{"host_id":"tf-api","provider":"terraform","spec":{
  "tenant_id":"platform-sre","environment":"production","package":"example.api",
  "target_version":"<sha256 of change.tfplan>","directory":"/srv/terraform/api",
  "plan_file":"change.tfplan"
}}]
```

Install Terraform separately (the API Docker image does not bundle it). Mount the
trusted initialized project, saved plan and scoped provider credentials. Generate and
review the plan outside OpsPilot; the configured resource address must be the only
non-no-op change, with action `update` and no unknown after-values. The artifact must
reside inside the configured project. Execution copies approved bytes into a private
artifact, verifies its hash and JSON, and applies exactly that file using argument
vectors without a shell. State verification compares the resource values to the
reviewed after-values. Project code/providers must also be trusted; Terraform plans
can invoke provisioners. No generic rollback or proof for a lost apply acknowledgement
is offered: inspect Terraform state and submit a new reviewed recovery plan.

## GitHub change request

```json
[{"host_id":"github-config","provider":"github","spec":{
  "tenant_id":"platform-sre","environment":"production","package":"config/service.yaml",
  "target_version":"<git blob SHA-1 of content>","repository":"your-org/your-repo",
  "base_ref":"main","content":"replicas: 3\n"
}}]
```

Set `OPSPILOT_GITHUB_TOKEN` to a credential scoped to the configured repository with
contents and PR write permissions. The target hash is Git's blob hash including its
header, not a plain SHA-1 of bytes. Files are limited to 64KiB. OpsPilot creates a
run-specific branch, updates the one file with a SHA precondition, and opens a draft
PR. It never merges. `WAITING_EXTERNAL` retains the host lease until a human merge
and explicit recovery verifies the base file. Closing without merging is a failed
postcheck requiring escalation. Partial branch/file writes without a unique matching
PR cannot prove completion and remain blocked for operator reconciliation.

## Timeouts and recovery

SDK mutation retries are disabled where applicable. The MCP session deadline is
180 seconds; backend calls use bounded request/command timeouts. Server calls run in
threads, so cancelling an MCP request does not stop an external call already in
flight. Unknown operations must be reconciled by receipt/remote proof, never replayed
blindly. Keep provider verification/command budgets below the session deadline and
worker lease; the default backend budgets are 60 seconds. There is no universal
exactly-once guarantee across a database and remote infrastructure API.
