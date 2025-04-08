#!/bin/python3
import configparser
import boto3
from botocore.exceptions import ClientError
import os
from datetime import datetime
import time
import sys
from threading import Thread, Event
import threading


def show_status_indicator():
    global indicator_running
    colors = [
        "\033[38;2;251;73;52m●\033[0m",  # Red
        "\033[38;2;250;189;47m●\033[0m",  # Yellow
        "\033[38;2;184;187;38m●\033[0m",  # Green
        "\033[38;2;131;165;152m●\033[0m"   # Teal
    ]
    current_color = 0
    sys.stdout.write('Working: ')
    while indicator_running:
        sys.stdout.write(colors[current_color] + ' ')
        sys.stdout.flush()
        current_color = (current_color + 1) % len(colors)
        time.sleep(0.5)  # Adjust the speed of the status indicator here
        sys.stdout.write('\rWorking: ')
    sys.stdout.write('\rDone!      \n')  # Clear the line when done


class StatusIndicator:
    def __init__(self, message="Working", interval=0.5):
        self.colors = ["\033[38;2;251;73;52m●\033[0m",
                       "\033[38;2;250;189;47m●\033[0m",
                       "\033[38;2;184;187;38m●\033[0m",
                       "\033[38;2;131;165;152m●\033[0m"
                       ]
        self.message = message
        self.interval = interval
        self.running = Event()

    def start(self):
        self.running.set()
        self.thread = Thread(target=self.run)
        self.thread.start()

    def run(self):
        current_color = 0
        sys.stdout.write(f'{self.message}: ')
        while self.running.is_set():
            sys.stdout.write(self.colors[current_color] + ' ')
            sys.stdout.flush()
            current_color = (current_color + 1) % len(self.colors)
            time.sleep(self.interval)
            sys.stdout.write('\r' + ' ' * (len(self.message) + 2) + '\r')
            sys.stdout.write(f'{self.message}: ')
        sys.stdout.write('\r' + ' ' * (len(self.message) + 2) + '\r')
        sys.stdout.write('Done!\n')

    def stop(self):
        self.running.clear()
        self.thread.join()

# Func to collect Profile variable(s)


def get_aws_profiles():
    """Read AWS profiles from ~/.aws/credentials."""
    aws_credentials_path = os.path.expanduser('~/.aws/credentials')
    config = configparser.ConfigParser()
    config.read(aws_credentials_path)
    return config.sections()

# Func to collect iam data (note this is global and region is usesless here)


def collect_iam_data(profile, selected_regions):
    session = boto3.Session(profile_name=profile)
    iam = session.client('iam')
    profile_data = []

    try:
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                user_name = user['UserName']
                keys_response = iam.list_access_keys(UserName=user_name)
                for key in keys_response['AccessKeyMetadata']:
                    access_key_id = key['AccessKeyId']
                    access_key_data = iam.get_access_key_last_used(AccessKeyId=access_key_id)
                    last_used_date = access_key_data['AccessKeyLastUsed'].get('LastUsedDate')

                    # Format date if it exists
                    formatted_date = last_used_date.strftime('%Y-%m-%d %H:%M:%S') if last_used_date else 'Never'

                    profile_data.append({
                        'Profile': profile,
                        'UserName': user_name,
                        'AccessKeyId': access_key_id,
                        'Status': key['Status'],
                        'CreationDate': key['CreateDate'].strftime('%Y-%m-%d %H:%M:%S'),
                        'Region': 'global',  # Since IAM is a global service
                        'LastUsedDate': formatted_date
                    })
    except ClientError as error:
        error_msg = error.response['Error']['Message']
        print(f"An error occurred with profile {profile}: {error_msg}")

    return profile_data


# Func to collect iam user variable(s)

def select_profiles(profiles):
    """
    Allow the user to select one, multiple, or all profiles.
    :param profiles: List of available profiles.
    :return: Tuple of selected profiles and selection mode ('all', 'many', 'one', or 'invalid').
    """
    print("\nEnter the numbers of the profiles you want to use, separated by commas (e.g., 1,2,3), or 'all' for all profiles:")

    while True:  # Loop until valid input is received or action is taken based on input
        selection = input().strip().lower()

        if selection == 'all':
            return profiles, 'all'

        selected_indices = selection.split(',')
        selected_profiles = []
        try:
            for index in selected_indices:
                # Trim whitespace around each index and convert to int
                selected_profiles.append(profiles[int(index.strip()) - 1])
            return selected_profiles, 'many' if len(selected_profiles) > 1 else 'one'
        except (ValueError, IndexError):
            print("Invalid selection. Please enter valid number(s) or 'all'.")
            # Optionally, you could limit the number of retries or implement additional handling here


def generate_iam_report(profile, regions):
    """Query IAM access keys and generate a Markdown report for the specified
    profile and regions."""
    session = boto3.Session(profile_name=profile)
    iam = session.client('iam')

    # Query IAM users
    users = iam.list_users()['Users']
    access_key_data = []

    for user in users:
        user_name = user['UserName']
        access_keys = iam.list_access_keys(UserName=user_name)['AccessKeyMetadata']
        for key in access_keys:
            key_info = iam.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
            last_used = key_info['AccessKeyLastUsed'].get('LastUsedDate', 'N/A')
            access_key_data.append({
                'Profile': profile,
                'Region': ', '.join(regions),  # Including regions as a string
                'IAM or Role Name': user_name,
                'Date Created': key['CreateDate'].strftime("%Y-%m-%d %H:%M:%S"),
                'Date Last Used': last_used.strftime("%Y-%m-%d %H:%M:%S") if last_used != 'N/A' else 'N/A',
                'Access Key': key['AccessKeyId'],
            })

    # Generate Markdown report with an added Region column
    report_content = "# IAM Access Key Report\n\n"
    report_content += f"**Profile:** {profile}\n"
    report_content += f"**Regions:** {', '.join(regions)}\n"  # Listing regions
    report_content += f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

    # Adding table headers, including Region
    report_content += "| Profile | Region | IAM or Role Name | Date Created | Date Last Used | Access Key |\n"
    report_content += "|---------|--------|------------------|--------------|----------------|------------|\n"

    # Adding data rows
    for row in access_key_data:
        report_content += f"| {row['Profile']} | {row['Region']} | {row['IAM or Role Name']} | {row['Date Created']} | {row['Date Last Used']} | {row['Access Key']} |\n"

    # Saving the report
    report_directory = os.path.expanduser(f'~/aws-reports/{profile}')
    os.makedirs(report_directory, exist_ok=True)
    report_filename = f"{profile}-iam-access-keys.md"
    report_path = os.path.join(report_directory, report_filename)

    with open(report_path, 'w') as report_file:
        report_file.write(report_content)

    print(f"Report generated: {report_path}")

# Get EKS Stuff


def fetch_eks_cluster_info(profile, region):
    """
    Fetches EKS clusters information for a given AWS profile and region.
    Returns a list of dictionaries with cluster details.
    """
    try:
        session = boto3.Session(profile_name=profile, region_name=region)
        eks = session.client('eks')
        clusters = eks.list_clusters()['clusters']

        cluster_details = []
        for cluster_name in clusters:
            details = eks.describe_cluster(name=cluster_name)['cluster']
            nodegroups = eks.list_nodegroups(clusterName=cluster_name)['nodegroups']

            # Initialize node count to 0
            total_nodes = 0
            for ng in nodegroups:
                ng_details = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng)['nodegroup']
                # Assuming desiredSize as the node count for simplicity
                total_nodes += ng_details['scalingConfig']['desiredSize']

            cluster_details.append({
                'Profile': profile,
                'Region': region,
                'Cluster Name': cluster_name,
                'Version': details['version'],
                'Nodes': total_nodes,
                'FIPS Enabled': details.get('resourcesVpcConfig', {}).get('endpointPrivateAccess', False)  # Example, adjust based on actual need
            })
        return cluster_details
    except Exception as e:
        print(f"Error fetching EKS cluster info for profile {profile} in region {region}: {e}")
        return []


def inventory_eks_clusters(selected_profile, selected_region):
    """
    Handles the inventory process for EKS clusters.
    """
    clusters_info = fetch_eks_cluster_info(selected_profile, selected_region)
    # Here, implement the logic to format and output the fetched data as per your report's requirements
    # For simplicity, printing the fetched information
    for cluster in clusters_info:
        print(cluster)


def worker_thread(profile, region):
    """
    A worker thread to handle the inventory for a given profile and region.
    Extend this to handle more AWS services as needed.
    """
    # Example service selection - extend this as needed
    service = 'EKS'  # This could be dynamic based on user input or script parameters
    if service == 'EKS':
        inventory_eks_clusters(profile, region)
    # Add more services here...
# Where we ask for region to run the script against if the service isn't global


def select_regions():
    """Allow the user to select one, multiple, or all AWS regions from a numbered list."""
    aws_regions = [
        'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
        'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3',
        'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2',
        'ap-south-1', 'sa-east-1', 'ca-central-1', 'eu-north-1',
    ]
    print("\nAvailable AWS Regions:")
    for i, region in enumerate(aws_regions, 1):
        print(f"{i}. {region}")
    print(f"{len(aws_regions) + 1}. All Regions")

    selected = input("Select regions by number (e.g., 1,3,5 or 'all' for all regions): ").strip().lower()
    if selected == 'all':
        return aws_regions  # Return all regions if 'all' is selected

    selected_indices = [int(index.strip()) - 1 for index in selected.split(',') if index.strip().isdigit()]
    selected_regions = [aws_regions[i] for i in selected_indices if 0 <= i < len(aws_regions)]

    return selected_regions

# UI stuff to choose service to inventory


def select_service():
    """Prompt the user to select an AWS service for inventory."""
    services = ['IAM']  # Placeholder for future service additions
    print("\nAvailable Services for Inventory:")
    for i, service in enumerate(services, 1):
        print(f"{i}. {service}")

    selection = input("Select a service by number: ").strip()
    try:
        selected_index = int(selection) - 1
        selected_service = services[selected_index]
    except (ValueError, IndexError):
        print("Invalid selection. Please enter a valid number.")
        return None

    return selected_service

# Define whether services are global or region-specific


service_characteristics = {
    'IAM': {'is_global': True},
    # Add other services here as needed, e.g., 'EC2': {'is_global': False},
}

# The main() function


def main():
    profiles = get_aws_profiles()
    print("\nAvailable AWS Profiles:")
    for i, profile in enumerate(profiles, 1):
        print(f"{i}. {profile}")

    selected_profiles, selection_type = select_profiles(profiles)
    if selection_type == 'invalid' or not selected_profiles:
        return  # Exit if no valid profiles are selected or if there was an error in selection

    selected_service = select_service()
    if not selected_service:
        return  # Exit if no valid service is selected

    # For global services, adjust the logic as previously described
    if service_characteristics.get(selected_service, {}).get('is_global', False):
        selected_regions = ['global']  # Placeholder for global services
    else:
        selected_regions = select_regions()

    global indicator_running
    indicator_running = True
    indicator_thread = threading.Thread(target=show_status_indicator)
    indicator_thread.start()

    aggregated_data = {}
    for profile in selected_profiles:
        if selected_service == 'IAM':
            profile_data = collect_iam_data(profile, selected_regions)
            aggregated_data[profile] = profile_data  # Store data for each profile
        else:
            print(f"Service {selected_service} inventory is not implemented yet.")
            return

    # Determine the report directory and filename based on the number of selected profiles
    if len(selected_profiles) > 1:
        report_directory = os.path.expanduser(f'~/aws-reports/aggregated')
        report_filename = f"aggregated-{selected_service}-report.md"
    else:
        report_directory = os.path.expanduser(f'~/aws-reports/{selected_profiles[0]}')
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        report_filename = f"{selected_profiles[0]}-{selected_service}-report-{timestamp}.md"

    # Generate IAM inventory report and save it to the specified directory with the specified filename
    generate_iam_inventory_report(aggregated_data, selected_profiles, selected_service, report_directory, report_filename)

    indicator_running = False
    indicator_thread.join()


def generate_iam_inventory_report(iam_data, selected_profiles, selected_service, report_directory, report_filename):
    """
    Generates a Markdown report aggregating IAM user data and access keys, including the 'Last Used Date'.

    :param iam_data: A dictionary containing IAM user data collected for each profile.
    :param selected_profiles: List of selected AWS profiles for the report.
    :param selected_service: The selected AWS service for which the report is generated.
    :param report_directory: The directory where the report will be saved.
    :param report_filename: The filename for the report.
    """
    # Determine the report directory based on the number of selected profiles
    if len(selected_profiles) > 1:
        report_directory = os.path.expanduser(f'~/aws-reports/aggregated')
    else:
        report_directory = os.path.expanduser(f'~/aws-reports/{selected_profiles[0]}')

    os.makedirs(report_directory, exist_ok=True)  # Ensure the directory exists

    # Generate report header including 'Last Used Date'
    header = f"# AWS {selected_service} Inventory Report\n\n"
    header += f"Profiles: {', '.join(selected_profiles)}\n"
    header += f"Action: IAM inventory collection\n"
    header += f"Date/Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

    # Write report header
    with open(os.path.join(report_directory, report_filename), 'w') as report_file:
        report_file.write(header)

        # Updated table header to include 'Last Used Date'
        report_file.write("| Profile | Region | IAM or Role Name | Access Key ID | Status | Creation Date | Last Used Date |\n")
        report_file.write("|---------|--------|------------------|---------------|--------|---------------|----------------|\n")
        for profile, users in iam_data.items():
            for user in users:
                # Ensure 'LastUsedDate' is included for each user, handle None values appropriately
                last_used_date = user.get('LastUsedDate', 'Never')  # Default to 'Never' if not available
                report_file.write(f"| {profile} | {user['Region']} | {user['UserName']} | {user['AccessKeyId']} | {user['Status']} | {user['CreationDate'].isoformat()} | {last_used_date} |\n")
    print(f"Report generated successfully at {os.path.join(report_directory, report_filename)}")

    if __name__ == "__main__":
        main()
