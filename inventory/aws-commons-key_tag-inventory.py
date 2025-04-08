#!/bin/python3
import boto3
import botocore
import os
import configparser


def get_profile_region(profile):
    """Retrieve the region for a given profile from the AWS config file."""
    aws_config_file = os.path.expanduser('~/.aws/config')
    config = configparser.ConfigParser()
    config.read(aws_config_file)
    profile_section = f"profile {profile}"
    # For the default profile, the section is just named "default"
    if profile == "heal":
        profile_section = profile
    if profile_section in config.sections():
        return config[profile_section].get('region')
    else:
        print(f"Region not found for profile {profile}. Please check your AWS config.")
        exit(1)


def list_profiles():
    """List AWS profiles available in the credentials file."""
    aws_credentials_file = os.path.expanduser('~/.aws/credentials')
    config = configparser.ConfigParser()
    config.read(aws_credentials_file)
    return config.sections()


def select_profile():
    """Prompt the user to select an AWS profile."""
    profiles = list_profiles()
    print("Available profiles:")
    for i, profile in enumerate(profiles, 1):
        print(f"{i}. {profile}")
    selection = int(input("Select a profile by number: "))
    return profiles[selection - 1]


def fetch_resources(profile):
    """Fetch resources and their tags for the selected profile."""
    session = boto3.Session(profile_name=profile)
    ec2 = session.client('ec2')
    resources = []

    try:
        # Example for EC2 instances
        instances = ec2.describe_instances()
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                for tag in instance.get('Tags', []):
                    resources.append({
                        'Profile': profile,
                        'Key': tag['Key'],
                        'Value': tag['Value'],
                        'Resource ARN': instance['InstanceId'],
                        'Resource State': instance['State']['Name']
                    })
    except botocore.exceptions.ClientError as e:
        print(f"An error occurred: {e}")
    return resources


def generate_markdown_report(resources):
    """Generate a Markdown report from the fetched resources."""
    markdown = "Profile | Key | Value | Resource ARN | Resource State\n"
    markdown += "---|---|---|---|---\n"
    for resource in resources:
        markdown += f"{resource['Profile']} | {resource['Key']} | {resource['Value']} | {resource['Resource ARN']} | {resource['Resource State']}\n"
    return markdown


def main():
    profile = select_profile()
    resources = fetch_resources(profile)
    report = generate_markdown_report(resources)
    report_file = "aws_resources_report.md"
    with open(report_file, "w") as f:
        f.write(report)
    print(f"Report generated: {report_file}")


if __name__ == "__main__":
    main()
