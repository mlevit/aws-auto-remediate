# AWS Auto Remediate

Open source application to instantly remediate common security issues through the use of AWS Config.

## Table of Contents

- [Setup](#setup)
  - [Deployment](#deployment)
  - [Removal](#removal)

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
   `cd aws-auto-remediate`

08. Install Serverless plugins

   ```bash
   serverless plugin install -n serverless-python-requirements
   npm install serverless-iam-roles-per-function
   ```

09. Deploy Auto Remediate

   ```bash
   serverless deploy
   ```

10. Invoke Auto Remediate Setup Config for the first time to create the necessary AWS Config rules

   ```bash
   serverless invoke -f AutoRemediateSetupConfig
   ```

11. Check Auto Remediate logs

   ```bash
   serverless logs -f AutoRemediateSetupConfig
   ```

### Removal

Auto Cleanup is deployed using the Serverless Framework which under the hood creates an AWS CloudFormation Stack. This means removal is clean and simple.

To remove Auto Remediate from your AWS account, follow the below steps:

1. Change into the Auto Remediate directory 
   `cd aws-auto-remediate`
2. Remove Auto Remediate 
   `serverless remove`