#!/usr/bin/python3
import os
import boto3
from datetime import datetime
from botocore.exceptions import ClientError
from pathlib import Path

# Define colors for user interface based on Gruvbox theme
class Gruvbox:
    DARK_GRAY = '\033[38;5;238m'
    LIGHT_GRAY = '\033[38;5;245m'
    YELLOW = '\033[38;5;172m'
    GREEN = '\033[38;5;142m'
    RED = '\033[38;5;167m'
    RESET = '\033[0m'

def get_profiles():
    """Fetches AWS profiles from the local AWS configuration."""
    aws_credentials_file = Path.home() / '.aws/credentials'
    if not aws_credentials_file.exists():
        print(f"{Gruvbox.RED}Credentials file not found. Please ensure AWS CLI is configured.{Gruvbox.RESET}")
        exit(1)
    with open(aws_credentials_file) as file:
        profiles = [line.split('[')[-1].split(']')[0] for line in file.readlines() if '[' in line]
    return profiles

def select_profiles(profiles):
    """Allows the user to select one or more AWS profiles."""
    for i, profile in enumerate(profiles):
        print(f"{Gruvbox.LIGHT_GRAY}{i + 1}. {profile}{Gruvbox.RESET}")
    
    choice = input(f"{Gruvbox.GREEN}Select profiles by number (comma-separated for multiple, 'a' for all, or enter to use default): {Gruvbox.RESET}")
    if choice.strip().lower() == 'a':
        return profiles
    selected_indices = [int(index) - 1 for index in choice.split(',') if index.isdigit() and 0 < int(index) <= len(profiles)]
    return [profiles[i] for i in selected_indices] if selected_indices else ['default']

def list_regions():
    """Returns a list of AWS regions."""
    return ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'eu-central-1', 'eu-west-1']

def select_regions():
    """Allows the user to select one or more AWS regions."""
    regions = list_regions()
    for i, region in enumerate(regions):
        print(f"{Gruvbox.LIGHT_GRAY}{i + 1}. {region}{Gruvbox.RESET}")
    choice = input(f"{Gruvbox.GREEN}Select regions by number (comma-separated for multiple, 'p' for a pattern like 'us-*', or enter to use default us-east-1): {Gruvbox.RESET}").strip().lower()
    if choice == 'p':
        return [region for region in regions if region.startswith('us-')]
    selected_indices = [int(index) - 1 for index in choice.split(',') if index.isdigit()]
    return [regions[i] for i in selected_indices] if selected_indices else ['us-east-1']

def user_action_choice():
    """Prompts the user to choose between managing IAM keys or generating an inventory report."""
    print(f"{Gruvbox.YELLOW}Select Action:{Gruvbox.RESET}")
    print(f"{Gruvbox.LIGHT_GRAY}1. Manage IAM Keys{Gruvbox.RESET}")
    print(f"{Gruvbox.LIGHT_GRAY}2. Generate IAM Inventory Report{Gruvbox.RESET}")
    return input(f"{Gruvbox.GREEN}Enter your choice (1 or 2): {Gruvbox.RESET}")

def list_iam_users(iam_client):
    """Lists IAM users."""
    try:
        return iam_client.list_users().get('Users', [])
    except ClientError as e:
        print(f"{Gruvbox.RED}Error listing IAM users: {e}{Gruvbox.RESET}")
        return []

def manage_access_keys(iam_client, user_name):
    """Manages IAM access keys for a specified user."""
    print(f"{Gruvbox.YELLOW}Managing Access Keys for {user_name}:{Gruvbox.RESET}")
    try:
        keys_response = iam_client.list_access_keys(UserName=user_name)
        if not keys_response.get('AccessKeys'):
            print(f"{Gruvbox.LIGHT_GRAY}No access keys found for {user_name}.{Gruvbox.RESET}")
            return

        for key in keys_response['AccessKeys']:
            print(f"{Gruvbox.LIGHT_GRAY}Access Key ID: {key['AccessKeyId']} - Status: {key['Status']}{Gruvbox.RESET}")
        action = input(f"{Gruvbox.GREEN}Select an action: [e]nable, [d]isable, [c]reate, [del]ete, [s]kip: {Gruvbox.RESET}").lower()
        access_key_id = input(f"{Gruvbox.GREEN}Enter Access Key ID: {Gruvbox.RESET}") if action in ['e', 'd', 'del'] else None

        if action == 'e':
            iam_client.update_access_key(UserName=user_name, AccessKeyId=access_key_id, Status='Active')
            print(f"{Gruvbox.GREEN}Access Key {access_key_id} enabled.{Gruvbox.RESET}")
        elif action == 'd':
            iam_client.update_access_key(UserName=user_name, AccessKeyId=access_key_id, Status='Inactive')
            print(f"{Gruvbox.GREEN}Access Key {access_key_id} disabled.{Gruvbox.RESET}")
        elif action == 'c':
            new_key = iam_client.create_access_key(UserName=user_name)
            print(f"{Gruvbox.GREEN}Created new Access Key: {new_key['AccessKey']['AccessKeyId']}{Gruvbox.RESET}")
        elif action == 'del':
            iam_client.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
            print(f"{Gruvbox.GREEN}Access Key {access_key_id} deleted.{Gruvbox.RESET}")
    except ClientError as e:
        print(f"{Gruvbox.RED}Error managing access keys for {user_name}: {e}{Gruvbox.RESET}")

def manage_iam_keys(session, regions):
    """Wrapper function for managing IAM keys across specified regions."""
    iam_client = session.client('iam')
    users = list_iam_users(iam_client)
    for user in users:
        manage_access_keys(iam_client, user['UserName'])

def generate_iam_inventory_report(session, profiles, regions):
    iam_client = session.client('iam')
    report_directory = Path.home() / 'aws/logs'
    report_directory.mkdir(parents=True, exist_ok=True)
    
    for profile in profiles:
        print(f"Processing profile: {profile}")
        report_path = report_directory / f'{profile}-iam_report.md'
        with open(report_path, 'w') as report_file:
            report_file.write(f"# IAM Inventory Report for Profile: {profile}\n")
            report_file.write("| Profile Name | IAM Name | Access Key ID | Access Key PW | Create Date | Last Used Date | Access Key Status |\n")
            report_file.write("|--------------|----------|---------------|---------------|-------------|----------------|-------------------|\n")
            
            users_response = iam_client.list_users()
            if 'Users' in users_response:
                for user in users_response['Users']:
                    user_name = user['UserName']
                    print(f"Fetching access keys for user: {user_name}")
                    keys_response = iam_client.list_access_keys(UserName=user_name)
                    
                    if keys_response and 'AccessKeys' in keys_response:
                        for key in keys_response['AccessKeys']:
                            access_key_id = key['AccessKeyId']
                            create_date = key['CreateDate'].strftime('%Y-%m-%d %H:%M:%S')
                            status = key['Status']
                            last_used_response = iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
                            last_used_date = 'Never'  # Default value
                            if 'AccessKeyLastUsed' in last_used_response and 'LastUsedDate' in last_used_response['AccessKeyLastUsed']:
                                last_used_date = last_used_response['AccessKeyLastUsed']['LastUsedDate'].strftime('%Y-%m-%d %H:%M:%S')
                            report_file.write(f"| {profile} | {user_name} | {access_key_id} | N/A | {create_date} | {last_used_date} | {status} |\n")
                        print(f"Processed {len(keys_response['AccessKeys'])} access keys for user: {user_name}")
                    else:
                        print(f"No access keys found for user: {user_name}")
            else:
                print("No IAM users found.")
        print(f"IAM Inventory Report generated at {report_path}")

def main():
    profiles = get_profiles()
    selected_profiles = select_profiles(profiles)
    print(f"{Gruvbox.YELLOW}Selected Profiles: {Gruvbox.RESET}{', '.join(selected_profiles)}")
    
    selected_regions = select_regions()  # Adjusted to call the correct function
    print(f"{Gruvbox.YELLOW}Selected Regions: {Gruvbox.RESET}{', '.join(selected_regions)}")

    action_choice = user_action_choice()
    
    for profile in selected_profiles:
        session = boto3.Session(profile_name=profile)
        if action_choice == '1':
            manage_iam_keys(session, selected_regions)
        elif action_choice == '2':
            generate_iam_inventory_report(session, [profile], selected_regions)

if __name__ == '__main__':
    main()
