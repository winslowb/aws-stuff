
# AWS Reporting Tools
## Overview
This repository contains a set of B scripts designed to generate various AWS reports. These scripts are helpful for AWS budget tracking, cost analysis, and usage monitoring.

Scripts Included:
- budgets_report - Generates a budget report for AWS profiles.
- cost_usage_report - Reports AWS cost and usage data.
- ec2_cost_report - Provides detailed cost reports specifically for EC2 - Other services.

## Prerequisites
- AWS CLI installed and configured with credentials.
- jq for parsing JSON data.
## Installation
Clone the repository to your local machine:

## Usage
1. Budgets Report (budgets_report)
This script generates a report detailing AWS budget information for selected profiles.
Running the Script:
` ./budgets_report `
Follow the prompts to select an AWS profile and generate a report.

2. Cost and Usage Report (cost_usage_report)
Generates a report on AWS cost and usage across different services.
Running the Script:
`./cost_usage_report`
Choose a profile, date range, granularity, and report format (Markdown or CSV) to generate the report.

3. EC2 Cost Report (ec2_cost_report)
Focuses on generating a cost report for EC2 - Other services.
Running the Script:
`./ec2_cost_report`
Select a profile, specify the date range and granularity, and the report will be generated.
