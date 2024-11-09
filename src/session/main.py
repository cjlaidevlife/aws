import boto3
import logging
import sys
import configparser
import os


def get_aws_session(profile_name):
    session = boto3.Session(profile_name=profile_name)
    sts_client = session.client("sts")
    iam_client = session.client("iam")
    return sts_client, iam_client


def get_current_user(sts_client):
    identity = sts_client.get_caller_identity()
    return identity.get("Arn").split("/")[-1]


def get_mfa_device(iam_client, user_name):
    mfa_devices_response = iam_client.list_mfa_devices(UserName=user_name)
    for mfa_info in mfa_devices_response.get("MFADevices"):
        mfa_devices_type = mfa_info.get("SerialNumber").split(":")[5].split("/")[0]
        if mfa_devices_type == "mfa":
            return mfa_info.get("SerialNumber")
    return None


def get_temporary_session_token(sts_client, mfa_device, mfa_token_code):
    sts_response = sts_client.get_session_token(
        SerialNumber=mfa_device, TokenCode=mfa_token_code
    )
    return sts_response.get("Credentials")


def update_credentials(profile_name, new_access_key, new_secret_key, new_session_token):
    credentials_path = os.path.expanduser("~/.aws/credentials")
    config = configparser.ConfigParser()
    config.read(credentials_path)

    if profile_name in config:
        config[profile_name]["aws_access_key_id"] = new_access_key
        config[profile_name]["aws_secret_access_key"] = new_secret_key
        config[profile_name]["aws_session_token"] = new_session_token

        with open(credentials_path, "w") as configfile:
            config.write(configfile)
        print(f"Profile '{profile_name}' updated successfully.")
    else:
        print(f"Profile '{profile_name}' not found in credentials file.")


def main():
    """
    Main function to handle AWS session management with MFA.

    This function performs the following steps:
    1. Parses command-line arguments to get source profile name, destination profile name, and MFA token code.
    2. Retrieves AWS session clients for STS and IAM using the source profile.
    3. Gets the current user and their MFA device.
    4. If an MFA device is found, it obtains a temporary session token using the MFA token code.
    5. Updates the AWS credentials for the destination profile with the temporary session token.

    Exceptions:
        IndexError: Raised when the required command-line arguments are not provided.
        Exception: Catches any other exceptions and prints an error message.
    """
    try:
        source_profile_name, destination_profile_name, mfa_token_code = sys.argv[1:4]

        sts_client, iam_client = get_aws_session(source_profile_name)
        current_user = get_current_user(sts_client)
        mfa_device = get_mfa_device(iam_client, current_user)

        if mfa_device:
            temporary_session_token = get_temporary_session_token(
                sts_client, mfa_device, mfa_token_code
            )
            update_credentials(
                destination_profile_name,
                temporary_session_token.get("AccessKeyId"),
                temporary_session_token.get("SecretAccessKey"),
                temporary_session_token.get("SessionToken"),
            )
        else:
            print("MFA device not found.")

    except IndexError as index_err:
        print(
            f"Input Argument Error: {index_err}, Argument Count: {len(sys.argv) - 1}, But We need Count: 3"
        )
    except Exception as unknow_err:
        print(f"Unknown Error: {unknow_err}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
