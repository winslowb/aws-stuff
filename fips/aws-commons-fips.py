#!/bin/python3

import boto3
import os
import time
import json

def list_profiles():
    credentials_path = os.path.join(os.path.expanduser('~'), '.aws', 'credentials')
    profiles = []
    with open(credentials_path, 'r') as f:
        for line in f:
            if line.startswith('[') and line.endswith(']\n'):
                profiles.append(line[1:-2])
    return profiles

def check_fips_status(instance_id, profile_name, region):
    session = boto3.Session(profile_name=profile_name, region_name=region)
    ssm_client = session.client('ssm')
    try:
        command_id = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={'commands': ['cat /proc/sys/crypto/fips_enabled']}
        )['Command']['CommandId']
        time.sleep(5)  # Wait for command execution
        output = ssm_client.get_command_invocation(
            CommandId=command_id,
            InstanceId=instance_id
        )['StandardOutputContent']
        return "Enabled" if output.strip() == "1" else "Disabled"
    except Exception as e:
        return "Check Manually"

def get_instance_details(tags):
    """Extract details from instance tags, identifying EKS nodes and their cluster names."""
    details = {'Type': 'General Purpose EC2', 'ClusterName': 'N/A'}
    for tag in tags:
        if tag['Key'].startswith('kubernetes.io/cluster/'):
            details['Type'] = 'EKS Node'
            details['ClusterName'] = tag['Key'].split('/')[-1]
        elif tag['Key'] == 'Name':
            details['Name'] = tag['Value']
    return details

def format_tags(tags):
    """Format the list of tag dictionaries into a readable string, limiting tag values to 20 characters."""
    return ', '.join([f"{tag['Key']}: {tag['Value'][:20]}" for tag in tags])

def generate_ec2_report(profile_name, region):
    report_filename = f"{profile_name}-{region}-fips.md"
    report_directory = os.path.join(os.path.expanduser('~'), 'aws-reports', profile_name)
    os.makedirs(report_directory, exist_ok=True)
    report_path = os.path.join(report_directory, report_filename)
    
    with open(report_path, 'w') as report_file:
        report_file.write("| Profile Name | Region | InstanceId | State | AMI ID | Type | Cluster Name | Tags | FIPS |\n")
        report_file.write("|--------------|--------|------------|-------|--------|------|--------------|------|------|\n")
        
        session = boto3.Session(profile_name=profile_name, region_name=region)
        ec2_client = session.client('ec2')
        response = ec2_client.describe_instances()
        
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                instance_state = instance['State']['Name']
                ami_id = instance['ImageId']  # Extract the AMI ID
                tags = instance.get('Tags', [])
                details = get_instance_details(tags)
                tags_formatted = format_tags(tags)
                fips_status = check_fips_status(instance_id, profile_name, region)
                
                report_file.write(f"| {profile_name} | {region} | {instance_id} | {instance_state} | {ami_id} | {details['Type']} | {details['ClusterName']} | {tags_formatted} | {fips_status} |\n")
        
    print(f"Report generated at {report_path}")
        
def main():
    profiles = list_profiles()
    print("Available AWS Profiles:")
    for i, profile in enumerate(profiles, start=1):
        print(f"{i}. {profile}")
    print(f"{len(profiles) + 1}. Quit")
    
    choice = input("Please select a profile by number: ")
    try:
        choice = int(choice)
        if choice == len(profiles) + 1:
            print("Exiting script.")
            return
        profile_name = profiles[choice - 1]
    except (ValueError, IndexError):
        print("Invalid choice. Exiting.")
        return
    
    region = input("Enter region (default us-east-1): ").strip() or 'us-east-1'
    generate_ec2_report(profile_name, region)

if __name__ == "__main__":
    main()
