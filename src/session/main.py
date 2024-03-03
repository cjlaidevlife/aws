import boto3
import logging
import sys
import configparser
import os


def main():
    """Update AWS Shared Configuration Profile.

    @BACKGROUND
      I can quickly configure the AWS Shared Configuration Profile by MFA Session Token.

    @TARGET
      replace the AWS Shared Configuration Profile.

    @ARGS
      * source_profile_name
      * destination_profile_name
      * mfa_token_code

    @AUTHOR
      cjlai

    """

    try:
        source_profile_name, destination_profile_name, mfa_token_code = (
            sys.argv[1],
            sys.argv[2],
            sys.argv[3],
        )

        session = boto3.Session(profile_name=source_profile_name)
        sts_session_client = session.client("sts")
        iam_session_client = session.client("iam")

        # get iam user friendly name from user profile
        identity = sts_session_client.get_caller_identity()
        current_friendly_name = identity.get("Arn").split("/")[-1]

        mfa_devices_response = iam_session_client.list_mfa_devices(
            UserName=current_friendly_name
        )
        for mfa_info in mfa_devices_response.get("MFADevices"):

            # get mfa devices from iam user
            mfa_devices_type = mfa_info.get("SerialNumber").split(":")[5].split("/")[0]
            current_mfa_device = mfa_info.get("SerialNumber")

            # condition for find first mfa devices
            if mfa_devices_type == "mfa":
                sts_response = sts_session_client.get_session_token(
                    SerialNumber=current_mfa_device, TokenCode=mfa_token_code
                )

                temporary_session_token = sts_response.get("Credentials")
                update_credentials(
                    destination_profile_name,
                    temporary_session_token.get("AccessKeyId"),
                    temporary_session_token.get("SecretAccessKey"),
                    temporary_session_token.get("SessionToken"),
                )
                sys.exit()

            else:
                print("Not Found Devices type is MFA!!")

    except IndexError as index_err:
        length = len(sys.argv)
        print(
            f"Input Argument Error: {index_err}, Argument Count: {length-1}, But We need Count: 3"
        )
        sys.exit()

    except Exception as unknow_err:
        print(f"Unknow Error: {unknow_err}")
        sys.exit()


@staticmethod
def update_credentials(
    profile_name: str, new_access_key: str, new_secret_key: str, new_session_token: str
):
    """update aws mfa credentials file

    this method from chatgpt prompt:

    How can I replace a specific profile in the AWS credentials file using Python?
    """
    credentials_path = "~/.aws/credentials"
    credentials_path = os.path.expanduser(credentials_path)

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


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    main()
