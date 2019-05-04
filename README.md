# AWS Auto Remediate

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/5bce55175d32494c89f0648b27719f43)](https://www.codacy.com/app/servian/aws-auto-remediate?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=servian/aws-auto-remediate&amp;utm_campaign=Badge_Grade)

Open source application to instantly remediate common security issues through the use of AWS Config.

## Table of Contents

- [About](#about)
- [Setup](#setup)
  - [Deployment](#deployment)
  - [Removal](#removal)
- [Rules](#rules)

## About

### Auto Remediate

The Auto Remediate function is triggered via an SNS Topic `auto-remediate-config-compliance-production`. The SNS Topic is populated with a compliance payload from AWS Config via a CloudWatch Event `auto-remediate-config-compliance-only-production`. The purpose of the CloudWatch Event is to filter out all non-compliance related messages that AWS Config generates.

Once the Lambda function has been triggered it will attempt to remediate the security concern. If the remediation was unsuccessful, the event payload will be sent to the dead letter queue (DQL) SQS Queue `auto-remediate-dlq-production`.

### Auto Remediate DLQ

The Auto Remediate DLQ function is triggered on a schedule (defined in the `serverless.yml` file). When the function is run, it will retrieve messages from SQS Queue `auto-remediate-dlq-production` and invoke the Auto Remediate Lambda function.

## Auto Remediate Setup

The Auto Remediate Setup function is triggered manually by the user. The purpose of this function is to invoke CloudFormation Stacks for each of the AWS Config Rules that will monitor for security issues as well as create/insert records into the DynamoDB settings table used to control the actions of the Auto Remediate function.

## Setup

### Deployment

To deploy this Auto Remediate to your AWS account, follow the below steps:

01. Install Serverless

```bash
npm install serverless -g
```

02. Install AWS CLI

```bash
pip3 install awscli --upgrade --user
```

03. Clone this repository

```bash
git clone https://github.com/servian/aws-auto-remediate
```

04. Configure AWS CLI following the instruction at [Quickly Configuring the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html#cli-quick-configuration). Ensure the user you're configuring has the appropriate IAM permissions to create Lambda Functions, S3 Buckets, IAM Roles, and CloudFormation Stacks. It is best for administrators to deploy Auto Remediate.

05. If you've configure the AWS CLI using a profile, open the `serverless.yml` file and modify the `provider > profile` attribute to match your profile name.

06. Change the custom `company` attribute within the `serverless.yml` file to your company name in order to prevent S3 Bucket name collision

07. Change into the Auto Remediate directory

```
cd aws-auto-remediate
```

08. Install Serverless plugins

```bash
serverless plugin install -n serverless-python-requirements
```

```bash
npm install serverless-iam-roles-per-function
```

09. Deploy Auto Remediate

```bash
serverless deploy
```

10. Invoke Auto Remediate Setup Config for the first time to create the necessary AWS Config rules

```bash
serverless invoke -f AutoRemediateSetup
```

11. Check Auto Remediate logs

```bash
serverless logs -f AutoRemediateSetup
```

### Removal

Auto Remediate is deployed using the Serverless Framework which under the hood creates an AWS CloudFormation Stack. This means removal is clean and simple.

To remove Auto Remediate from your AWS account, follow the below steps:

1. Change into the Auto Remediate directory

```bash
cd aws-auto-remediate
```

2. Remove Auto Remediate

```bash
serverless remove
```

## Rules

The table below details the auto remediated rules and scenarios.

### AWS Config Managed Rules

#### Compute

| Rule                                                         |
| :----------------------------------------------------------- |
| [restricted-ssh](https://docs.aws.amazon.com/config/latest/developerguide/restricted-ssh.html)<br />Checks whether the incoming SSH traffic for the security groups is accessible. The rule is COMPLIANT when the IP addresses of the incoming SSH traffic in the security groups are restricted. This rule applies only to IPv4. |

#### Database

| Rule                                                         |
| :----------------------------------------------------------- |
| [rds-instance-public-access-check](https://docs.aws.amazon.com/config/latest/developerguide/rds-instance-public-access-check.html)<br />Check whether the Amazon Relational Database Service instances are not publicly accessible. The rule is NON_COMPLIANT if the `publiclyAccessible` field is true in the instance configuration item. |

#### Security, Identity & Compliance

| Rule                                                         |
| :----------------------------------------------------------- |
| [access-keys-rotated](https://docs.aws.amazon.com/config/latest/developerguide/access-keys-rotated.html)<br />Checks whether the active access keys are rotated within the number of days specified in `maxAccessKeyAge`. The rule is NON_COMPLIANT if the access keys have not been rotated for more than `maxAccessKeyAge` number of days.`` |