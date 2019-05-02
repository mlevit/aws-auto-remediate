# AWS Auto Remediate

Open source application to instantly remediate common security issues through the use of AWS Config.

## Table of Contents

- [Setup](#setup)
  - [Deployment](#deployment)
  - [Removal](#removal)

## Setup
### Deployment

To deploy this Auto Remediate to your AWS account, follow the below steps:

1. Install Serverless
   `npm install serverless -g`
2. Install AWS CLI 
   `pip3 install awscli --upgrade --user`
3. Clone this repository 
   `git clone https://github.com/servian/aws-auto-remediate`
4. Configure AWS CLI following the instruction at [Quickly Configuring the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html#cli-quick-configuration). Ensure the user you're configuring has the appropriate IAM permissions to create Lambda Functions, S3 Buckets, IAM Roles, and CloudFormation Stacks. It is best for administrators to deploy Auto Remediate.
5. If you've configure the AWS CLI using a profile, open the `serverless.yml` file and modify the `provider > profile` attribute to match your profile name.
6. Change the custom `company` attribute within the `serverless.yml` file to your company name in order to prevent S3 Bucket name collision
7. Change into the Auto Remediate directory 
   `cd aws-auto-remediate`
8. Install Serverless plugin 
   `serverless plugin install -n serverless-python-requirements`
9. Deploy Auto Remediate 
   `serverless deploy`
10. Invoke Auto Remediate for the first time 
      `serverless invoke -f AutoRemediate`
11. Check Auto Remediate logs 
      `serverless logs -f AutoRemediate`

### Removal

Auto Cleanup is deployed using the Serverless Framework which under the hood creates an AWS CloudFormation Stack. This means removal is clean and simple.

To remove Auto Remediate from your AWS account, follow the below steps:

1. Change into the Auto Remediate directory 
   `cd aws-auto-remediate`
2. Remove Auto Remediate 
   `serverless remove`