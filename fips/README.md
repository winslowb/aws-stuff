# AWS EC2 FIPS Status Reporter

This script inventories EC2 instances in profiles defined in your $HOME/.aws/credentials file. Only the python script will be maintained. 

## Features

- Checks status of /proc/fips
- Checks EC2 instance details (Instance ID, State, AMI ID, and truncated tags.)
- EKS nodes and reporting their cluster names.
- Reports are saved in a organized manner

## Prerequisites

- Python 3.x
- Boto3
- AWS CLI configured with access to the target AWS account(s).
- IAM permissions for listing EC2 instances and querying their FIPS status via AWS Systems Manager (SSM).

## Setup

1. **Install Boto3**: If not already installed, you can install Boto3 using pip:
    ```
    pip install boto3
    ```

2. **Configure AWS CLI**: Ensure that AWS CLI is configured with profiles for the AWS accounts you intend to query. You can configure profiles using:
    ```
    aws configure --profile profile-name
    ```
## Run it

Follow the on-screen prompts to select the AWS profile(s) and region for the report.

   ```
     ./aws-commons-fips.py
     ```

Reports are generated in Markdown format and saved in the following directory structure: $HOME/aws-reports/<profile_name>/<profile_name>-<region>-fips.md. 

