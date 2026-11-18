# Terraform

Infrastructure for the DevSecOps pipeline, managed as code.

## Layout

| Path | Purpose | State |
|---|---|---|
| `bootstrap/` | Creates the S3 bucket that stores state for everything else | Local (never committed) |

More configurations will be added in later stages (imported existing resources, CI plan, role split).

## Prerequisites

- Terraform >= 1.10
- AWS CLI signed in as an IAM admin user (not root): `aws sts get-caller-identity` should show `user/...`

## Stage 1: create the state bucket

```bash
cd terraform/bootstrap
terraform init
terraform fmt -check
terraform validate
terraform plan -out=tfplan
terraform apply tfplan
terraform output state_bucket_name
```

Read the plan before applying. Expect 5 resources to be added and nothing changed or destroyed:
the bucket, versioning, encryption, public access block and bucket policy.

The bootstrap state file stays on the machine that ran it (it is git-ignored). The bucket has
`prevent_destroy` set, so Terraform refuses to delete it.
