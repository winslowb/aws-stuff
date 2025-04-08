#!/usr/bin/python3
""" long story short, originally i thought i could use iam roles and polices to prvent cross uploading to repositories, but no matter how i tried, i was unsuccessfull; i'd provioned roles with iam policies similar to what you see below in the ecr functions.

then i was like *screw this* and tried to apply policies to the repositories. no matter how i tried i could not make it so. i can maually apply a policy to a repo but i can't get this script to go. there is a json file for the policy in test/ that i've used to manually ecr set-repository-policy. take a peek if you want.

i left the role_policy function jic i want to go backe to roles and attached policies.

also, the function 'def schedule_cleanup(role_name, expiration_time): ' is used to trouble shooting...i didn't want to wait around for shit to expire...so i sped it up
    > current_time = datetime.datetime.now(datetime.timezone.utc)
    > wait_seconds_initial = (expiration_time - current_time).total_seconds()
    > wait_seconds_initial = max(wait_seconds_initial - 3500, 0) # change this number ( in this instance even though the default is 3600 seconds it's actually cleaning up 100 seconds

i'm off on break for the next two weeks, but if you reading this and want to give it a go...go for it...happy holidays
"""
"""
To run:
- pip install -r requirements.txt
- python create_ecr_repo_and_creds.py
"""

import json
import threading
import time
import datetime
import logging

import boto3
from botocore.exceptions import BotoCoreError, ClientError


# ansi colors for log
class LogColors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"


AWS_ACCOUNTS = {
    "brh staging": "143731057154",
    "brh prod": "471112792849",
}


class CustomFormatter(logging.Formatter):
    format_dict = {
        logging.INFO: LogColors.GREEN + "%(message)s" + LogColors.RESET,
        logging.ERROR: LogColors.RED + "%(message)s" + LogColors.RESET,
    }

    def format(self, record):
        log_fmt = self.format_dict.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


def get_logger(name, log_level="info"):
    logger = logging.getLogger(name)
    logger.setLevel(logging.getLevelName(log_level.upper()))

    # Setting the custom formatter
    ch = logging.StreamHandler()
    ch.setFormatter(CustomFormatter())
    logger.addHandler(ch)

    return logger


logger = get_logger("create_ecr_repo_and_creds", log_level="info")


def create_user_role(profile_name, user_name, aws_account):
    boto3.setup_default_session(profile_name=profile_name)
    iam_client = boto3.client("iam", region_name="us-east-1")
    role_name = f"{user_name}-ECRUploadRole"
    assume_role_policy_document = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{aws_account}:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    try:
        # Check if the IAM role exists
        iam_client.get_role(RoleName=role_name)
        reuse = (
            input(f"Role '{role_name}' already exists. Reuse it? (y/n): ")
            .strip()
            .lower()
        )

        if reuse == "y":
            logger.info(f"* Reusing existing role '{role_name}'.")
            return role_name
        else:
            delete = (
                input(
                    f"This will delete the existing role '{role_name}' and recreate it. Do you confirm? (y/n): "
                )
                .strip()
                .lower()
            )
            if delete == "y":
                # Detach policies before deleting the role
                attached_policies = iam_client.list_attached_role_policies(
                    RoleName=role_name
                )
                for policy in attached_policies["AttachedPolicies"]:
                    iam_client.detach_role_policy(
                        RoleName=role_name, PolicyArn=policy["PolicyArn"]
                    )

                try:
                    iam_client.delete_role(RoleName=role_name)
                    logger.info(f"* Deleted existing role '{role_name}'.")
                except iam_client.exceptions.DeleteConflictException:
                    logger.error(
                        f"* Role '{role_name}' is still in use, cannot delete."
                    )
                    raise
                except ClientError as e:
                    logger.error(f"* ClientError during role deletion: {e}")
                    raise
                except Exception as e:
                    logger.error(
                        f"* Unexpected error during role deletion: {type(e).__name__}: {e}"
                    )
                    raise
            else:
                return role_name

    except iam_client.exceptions.NoSuchEntityException:
        # Role does not exist, continue to create a new one
        pass

    try:
        iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=assume_role_policy_document,
            Description=f"Role for user '{user_name}' to upload to ECR",
            MaxSessionDuration=43200,
        )

        logger.info(f"* Role '{role_name}' created successfully.")
        return role_name
    except ClientError as e:
        logger.error(f"* An error occurred while creating the role: {e}")
        raise
    except BotoCoreError as e:
        logger.error(f"* BotoCoreError occurred: {e}")
        raise
    except Exception as e:
        logger.error(f"* Unexpected error: {type(e).__name__}: {e}")
        raise


def create_temporary_credentials(
    profile_name, user_name, duration_seconds, aws_account
):
    try:
        session = boto3.Session(profile_name=profile_name, region_name="us-east-1")
        sts_client = session.client("sts", region_name="us-east-1")

        user_role_name = create_user_role(profile_name, user_name, aws_account)
        try:
            # Create temporary credentials for the users IAM role with a 12 hour expiration
            assumed_role_object = sts_client.assume_role(
                RoleArn=f"arn:aws:iam::{aws_account}:role/{user_role_name}",
                RoleSessionName=user_name,
                DurationSeconds=duration_seconds,
            )
        # If we get access denied, sleep for 10 sec and try again. This is to avoid hitting a race condition
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDenied":
                logger.info(
                    f"* Access denied. Sleeping for 10 seconds and trying again. Possible race condition."
                )
                time.sleep(10)
                assumed_role_object = sts_client.assume_role(
                    RoleArn=f"arn:aws:iam::{aws_account}:role/{user_role_name}",
                    RoleSessionName=user_name,
                    DurationSeconds=duration_seconds,
                )
            else:
                raise e
        credentials = assumed_role_object["Credentials"]
        logger.info(
            f"* Temporary credentials for role '{user_role_name}' created successfully."
        )

        return credentials, user_role_name

    except (BotoCoreError, ClientError) as error:
        logger.error(f"* Error occurred while creating temporary credentials: {error}")
        raise


def create_policy_document(repository_arn):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:BatchGetImage",
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:PutImage",
                    "ecr:InitiateLayerUpload",
                    "ecr:UploadLayerPart",
                    "ecr:CompleteLayerUpload",
                    "ecr:GetAuthorizationToken",
                ],
                "Resource": repository_arn,
            },
            {"Effect": "Allow", "Action": "ecr:GetAuthorizationToken", "Resource": "*"},
        ],
    }
    return json.dumps(policy)


"""
i can't get this policy to apply. i can apply it manually but not progormatically iv'e tried passing as json strings as well as making it a dict. i'm stumped atm
"""


def create_and_apply_ecr_repository_policy(ecr_client, repository_name, role_arn):
    repository_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": role_arn},
                "Action": [
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:BatchGetImage",
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:PutImage",
                    "ecr:InitiateLayerUpload",
                    "ecr:UploadLayerPart",
                    "ecr:CompleteLayerUpload",
                    "ecr:GetAuthorizationToken",
                ],
            }
        ],
    }

    policy_text = json.dumps(repository_policy)
    logger.info(
        f"Applying policy to repository '{repository_name}' with principal '{role_arn}'"
    )
    logger.info(
        f"Applying the following policy to ECR repository '{repository_name}': {policy_text}"
    )

    try:
        ecr_client.set_repository_policy(
            repositoryName=repository_name, policyText=policy_text
        )
        logger.info(f"* ECR repository policy set for '{repository_name}'.")
    except ClientError as e:
        logger.error(f"* Error setting ECR repository policy: {e}")
        raise


def create_ecr_repository(user_name, user_role_name, aws_account):
    ecr_client = boto3.client(
        "ecr",
        region_name="us-east-1",
    )
    repo_name = f"nextflow-staging/{user_name}"

    # Define role_arn here
    role_arn = f"arn:aws:iam::{aws_account}:role/{user_role_name}"

    try:
        try:
            response = ecr_client.create_repository(repositoryName=repo_name)
            repository_arn = response["repository"]["repositoryArn"]
            repository_uri = response["repository"]["repositoryUri"]
            logger.info(f"* ECR repository '{repo_name}' created successfully.")
        except ecr_client.exceptions.RepositoryAlreadyExistsException:
            logger.info(
                f"* ECR repository '{repo_name}' already exists. Continuing with existing repository."
            )
            response = ecr_client.describe_repositories(repositoryNames=[repo_name])
            if "repositories" in response and len(response["repositories"]) > 0:
                repository_arn = response["repositories"][0]["repositoryArn"]
                repository_uri = response["repositories"][0]["repositoryUri"]
            else:
                logger.error(
                    f"Failed to retrieve existing repository details for '{repo_name}'."
                )
                raise

        # TODO: Not sure if we need to apply policy to ECR repo. I think we only need this for the IAM role per user.
        # create_and_apply_ecr_repository_policy(ecr_client, repo_name, role_arn)

        return repository_uri, repository_arn
    except ClientError as e:
        logger.error(f"* ClientError in create_ecr_repository: {e}")
        raise
    except Exception as e:
        logger.error(
            f"* Unexpected error in create_ecr_repository: {type(e).__name__}: {e}"
        )
        raise


# munging role, policy names
def escapism(string):
    """
    This is a direct translation of Hatchery's `escapism` golang function to python.
    We need to escape the username in the same way it's escaped by Hatchery's `escapism` function because
    special chars cannot be used in an ECR repo name, and so that the ECR repo generated here matches the
    name expected by Hatchery.
    """

    safeBytes = "abcdefghijklmnopqrstuvwxyz0123456789"
    escaped = ""
    for v in string:
        if v not in safeBytes:
            hexCode = "{0:02x}".format(ord(v))
            escaped += "-" + hexCode
        else:
            escaped += v
    logger.info(f"* String '{string}' was escaped to '{escaped}'")
    return escaped


# cleanup stuff right here
def schedule_cleanup(role_name, expiration_time):
    current_time = datetime.datetime.now(datetime.timezone.utc)
    wait_seconds_initial = (expiration_time - current_time).total_seconds()

    wait_seconds_initial = max(wait_seconds_initial - 3500, 0)

    if wait_seconds_initial > 0:
        logger.info(f"Cleanup scheduled in {int(wait_seconds_initial)} seconds.")

        wait_seconds_countdown = wait_seconds_initial
        while wait_seconds_countdown > 0:
            mins, secs = divmod(wait_seconds_countdown, 60)
            timeformat = "{:02d}:{:02d}".format(int(mins), int(secs))
            print(f"Starting cleanup in: {timeformat}", end="\r")
            time.sleep(1)
            wait_seconds_countdown -= 1

        # start cleanup thread after countdown
        cleanup_thread = threading.Thread(target=cleanup_role, args=(role_name,))
        cleanup_thread.start()
    else:
        logger.info("No cleanup scheduled as the wait time has passed.")


def cleanup_role(role_name):
    logger.info(f"Starting cleanup.")

    # role cleanup
    iam_client = boto3.client("iam")
    try:
        iam_client.delete_role(RoleName=role_name)
        logger.info(f"* Role '{role_name}' deleted successfully.")
    except ClientError as e:
        logger.error(f"* ClientError during role deletion: {e}")
        raise
    except Exception as e:
        logger.error(
            f"* Unexpected error during role deletion: {type(e).__name__}: {e}"
        )
        raise


# function to update IAM role policy to allow for ECR push
def update_iam_role_policy(role_name, repository_arn, aws_account):
    policy_document = create_policy_document(repository_arn)
    iam_client = boto3.client("iam", region_name="us-east-1")
    policy_name = f"{role_name}-ECRPolicy"

    # try / catch
    try:
        policy = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=policy_document
        )
        policy_arn = policy["Policy"]["Arn"]

    except iam_client.exceptions.EntityAlreadyExistsException:
        # policy already exists, use existing policy
        logger.info(f"* Policy '{policy_name}' already exists. Reusing it.")
        policy_arn = iam_client.get_policy(
            PolicyArn=f"arn:aws:iam::{aws_account}:policy/{policy_name}"
        )["Policy"]["Arn"]
    except ClientError as e:
        logger.error(f"* Error creating policy: {e}")
        raise

    # attach policy to role
    try:
        iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        logger.info(
            f"* Policy '{policy_name}' attached to role '{role_name}' successfully."
        )
    except ClientError as e:
        logger.error(f"* Error attaching policy to role: {e}")
        raise


# let there be main
def main():
    profile_name = input("Enter the AWS profile name to use: ").strip()
    user_name = input(
        "Enter the username for which to create temporary credentials: "
    ).strip()
    aws_account = None
    while not aws_account:
        aws_account_name = (
            input(
                f"Which system are the creds for? Choose one of: {list(AWS_ACCOUNTS.keys())} "
            )
            .strip()
            .lower()
        )
        aws_account = AWS_ACCOUNTS.get(aws_account_name)

    user_name = escapism(user_name)
    duration = 3600  # 60 minutes. TODO: get this up to 12 hours
    temp_credentials, user_role_name = create_temporary_credentials(
        profile_name, user_name, duration, aws_account
    )
    repository_uri, repository_arn = create_ecr_repository(
        user_name, user_role_name, aws_account
    )
    update_iam_role_policy(user_role_name, repository_arn, aws_account)

    # logging stuff
    logger.info("Done! See output below.")
    print(f"\nECR Repository URI: {repository_uri}")
    print(
        f"Here are your temporary credentials. Please note that they will expire in {LogColors.RED}{duration} seconds{LogColors.RESET}."
    )
    print("\n\nPlease run the following commands to set your AWS credentials:\n")
    print(
        f"{LogColors.YELLOW}export AWS_ACCESS_KEY_ID='{LogColors.RESET}{temp_credentials['AccessKeyId']}'"
    )
    print(
        f"{LogColors.YELLOW}export AWS_SECRET_ACCESS_KEY='{LogColors.RESET}{temp_credentials['SecretAccessKey']}'"
    )
    print(
        f"{LogColors.YELLOW}export AWS_SESSION_TOKEN='{LogColors.RESET}{temp_credentials['SessionToken']}'\n"
    )

    print(
        "\nAfter setting credentials you will need to log in to your docker registry. Please run the following command:\n",
        "\n",
        f"{LogColors.YELLOW}aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin {repository_uri}{LogColors.RESET}\n",
        "\n"
        "You can push docker images to this repository using the following command:\n",
        "\n",
        f"{LogColors.YELLOW}docker push {repository_uri}:<tag>{LogColors.RESET}\n",
        "\n"
        "See the documentation about uploading Docker images here: https://uc-cdis.github.io/BRH-documentation/nextflow-upload-docker/\n",
    )

    # We don't need to clean up the role, as the credentials will expire automatically. Keeping this in, just in case I'm wrong (JQ)
    # expiration_time = temp_credentials['Expiration']
    # schedule_cleanup(user_role_name, expiration_time)


if __name__ == "__main__":
    main()
