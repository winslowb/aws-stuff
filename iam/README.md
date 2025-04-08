# AWS IAM Keys Management Script
## Description
[This Bash script](https://github.com/bwinsl0w/aws-stuff/tree/main/iam) is designed to manage AWS IAM user access keys across multiple profiles. It allows for various operations like creating, disabling, deleting, and inventorying access keys, as well as deleting users. The script is tailored for environments with multiple AWS profiles, providing flexibility in selecting specific IAM users either from AWS profiles directly or from a predefined list.

## Features
* Multiple Profile Support: Manage IAM keys across various AWS profiles.
* Selective User Operations: Choose specific IAM users for key management.
* User List Customization: Option to use AWS profile users or a predefined user list.
* Versatile Key Management: Supports creating, disabling, deleting, enabling keys, and more.
* Action-Specific Reports: Generates markdown reports with details of performed actions.

## Prerequisites
* AWS CLI installed and configured with the necessary AWS profiles.
* jq for parsing JSON data.

## Installation
* Clone the repository:
* Run the script:
` aws-commons-iam-keys `
* Follow the interactive prompts to select the AWS profile, source of IAM users, and the action to perform.

## Script Options
* Profile Selection: Choose an individual profile or 'All' for all profiles.
* User Source Selection: Select 'From AWS Profile' or 'From File' to specify the source of IAM users.

## Defined functions in the sctipt (aka Actions)
The _Actions_ function section does this stuff
* Actions:
- disable-key: Disables the access key for selected users.

- create-key: Creates a new access key for selected users.

- delete-key: Deletes the access key for selected users.

- enable-key: Enables the access key for selected users.

- inventory: Generates an inventory of access keys for selected users.

- delete-user: Deletes the selected IAM user.
