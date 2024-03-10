import boto3
import logging
import pandas as pd


def main():
    profile_name = "lab"

    boto3_session = boto3.Session(profile_name=profile_name)
    sts_client = boto3_session.client("sts")
    caller_identity = sts_client.get_caller_identity()
    logging.info(f"validtion: %s", caller_identity.get("Arn"))

    ipam_scope_ids = get_ipam_scope_ids(boto3_session)
    public_data = get_cidr_data(boto3_session, ipam_scope_ids[1], "public")
    # TBD: cann't get current private ip address
    private_data = get_cidr_data(boto3_session, ipam_scope_ids[1], "private")

    prepare_data = []
    prepare_data.extend(public_data)
    prepare_data.extend(private_data)
    
    df = pd.DataFrame.from_dict(prepare_data)
    df.to_excel(f'{profile_name}_players.xlsx')


@staticmethod
def get_ipam_scope_ids(session: object) -> tuple[int, dict]:
    """Get the ipam scopes count(int) and the ipam scopes list(dict)
    @author cjlai
    """

    ec2_client = session.client("ec2")
    ipam_scopes = ec2_client.describe_ipam_scopes().get("IpamScopes")
    ipam_scopes_count = len(ipam_scopes)
    ipam_scopes_dist = {}
    for ipam_scope in ipam_scopes:
        ipam_scopes_dist[ipam_scope.get("IpamScopeType")] = ipam_scope.get(
            "IpamScopeId"
        )

    return ipam_scopes_count, ipam_scopes_dist

@staticmethod
def get_cidr_data(session: object, scopes_dist: dict, scopes_type: str) -> list[dict]:
    """Get the cidr data of the ipam scopes
    @author cjlai
    """    
    ec2_client = session.client("ec2")

    resource_cidr_data = ec2_client.get_ipam_resource_cidrs(
        IpamScopeId=scopes_dist.get(scopes_type)
    ).get("IpamResourceCidrs")

    return resource_cidr_data

if __name__ == "__main__":
    logging.basicConfig(
        format="%(levelname)s %(asctime)s %(message)s",
        datefmt="%m/%d/%Y %I:%M:%S %p",
        level=logging.INFO,
    )
    main()
