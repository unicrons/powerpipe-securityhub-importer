# Powerpipe AWS SecurityHub Findings Importer

Import your [Powerpipe](https://powerpipe.io/) AWS ASFF findings into AWS SecurityHub in all your AWS Accounts and Regions!


## What is this?

*powerpipe-securityhub-importer* is tool that imports Powerpipe ASFF findings from different AWS Accounts and Regions into AWS SecurityHub.

We have created this tool to facilitate the integration between Powerpipe and AWS SecurityHub when working with different AWS Accounts and Regions.

When working with AWS SecurityHub findings from multiple accounts or regions, it is required to import the findings into **their** account and region.


## Features

- Import Powerpipe ASFF findings into AWS SecurityHub for each AWS Account and Region.
- Skip `PASSED` and `NOT_AVAILABLE` findings if desired.
- It is fast! :rocket:

> [!NOTE]
> Are you using Steampipe in your AWS Organizations? Check [steampipe-config-generator](https://github.com/unicrons/steampipe_config_generator) tool!

## Requirements

- An AWS IAM Role deployed in all your AWS accounts with:
  - A trust policy that allows `sts:AssumeRole` from a central role.
  - Permissions to import SecurityHub findings:
  ```json
  {
    "Sid": "SecurityHubImport",
    "Effect": "Allow",
    "Action": [
      "securityhub:BatchImportFindings"
    ],
    "Resource": "*"
  }
  ```
- Valid AWS credentials with the needed permissions to assume the distributed IAM Role:
  ```json
  {
    "Sid": "AssumeSecurityImportRole",
    "Effect": "Allow",
    "Action": [
      "sts:AssumeRole"
    ],
    "Resource": "arn:aws:iam::*:role/role-name-with-path"
  }
  ```

> [!TIP]
> Check our post [Deploy IAM Roles across an AWS Organization as code](https://unicrons.cloud/en/2024/10/14/deploy-iam-roles-across-an-aws-organization-as-code/) to know how to deploy the needed IAM role in all your AWS accounts!


## How to use it

```bash
Usage of powerpipe-securityhub-importer:
  -failed
    	Skip Importing PASSED & NOT_AVAILABLE findings
  -findings string
    	SecurityHub asff json file path
  -log string
    	Log format: default, json (default "default")
  -role string
    	AWS assume role name
  -session string
    	AWS assume role session name (default "powerpipe-securityhub-importer")
```

Example:
```bash
./powerpipe_securityhub_importer -findings ./findings.asff.json -role role-name-with-path
```

To skip `PASSED` and `NOT_AVAILABLE` findings add `-failed` flag.


## Contribute

Do you see any issue? Something to improve? A new feature? Open a Github Issue or submit a PR!   
We welcome all contributors!
