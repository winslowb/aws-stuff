import boto3
from botocore.exceptions import ProfileNotFound, NoCredentialsError, PartialCredentialsError
import os


def list_python_runtimes_for_profile(profile_name):
    """List Python runtimes for Lambda functions under a given AWS profile."""
    try:
        # Create a session using a specific profile and set the region to 'us-east-1'
        session = boto3.Session(profile_name=profile_name, region_name='us-east-1')
        # Create a Lambda client from this session
        lambda_client = session.client('lambda')
        # Retrieve a list of all Lambda functions
        response = lambda_client.list_functions()
        functions = response.get('Functions', [])
        # Filter and output Python runtimes
        python_runtimes = [{
            'Profile': profile_name,
            'FunctionName': function['FunctionName'],
            'Runtime': function['Runtime']
        } for function in functions if 'python' in function['Runtime'].lower()]
        return python_runtimes
    except (NoCredentialsError, PartialCredentialsError) as e:
        return f"Error accessing credentials: {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"


def generate_markdown_report(data):
    """Generate a Markdown formatted report from the data."""
    with open('lambda_python_versions_report.md', 'w') as file:
        file.write('| Profile Name | Job Name | Python Version |\n')
        file.write('|--------------|----------|----------------|\n')
        for entry in data:
            file.write(f"| {entry['Profile']} | {entry['FunctionName']} | {entry['Runtime']} |\n")
    print("Report saved as 'lambda_python_versions_report.md'")


def main():
    # Path to the AWS credentials file
    credentials_path = os.path.expanduser('~/.aws/credentials')
    if not os.path.exists(credentials_path):
        print("AWS credentials file not found.")
        return

    all_runtimes = []
    # Read the profile names from the credentials file
    profile_names = []
    with open(credentials_path, 'r') as file:
        for line in file:
            if line.startswith('[') and line.endswith(']\n'):
                profile_name = line[1:-2]
                profile_names.append(profile_name)

    # Collect Python runtimes for each profile's Lambda functions
    for profile in profile_names:
        runtimes = list_python_runtimes_for_profile(profile)
        if isinstance(runtimes, list):
            all_runtimes.extend(runtimes)
        else:
            print(f"Failed to retrieve runtimes for profile {profile}: {runtimes}")

    # Generate Markdown report
    if all_runtimes:
        generate_markdown_report(all_runtimes)
    else:
        print("No Python Lambda functions found or unable to access Lambda functions.")


if __name__ == "__main__":
    main()
