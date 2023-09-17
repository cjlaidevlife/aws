import re
import boto3
import logging

def main(): 
    """透過來源PROFILE上的使用者名稱、MFA設備類型及相對應的MFA TOKEN來產生臨時的SESSION TOKEN.
    @BACKGROUND
      IAM有限制ENABLE MFA DIVICE, 且透過ASSUME ROLE管理MULTI AWS ACCOUNT時的應用場景.
    @TARGET    
      不想要每次都得輸入很長的指令, 且可以省去手動寫入SHARED CREDENTIALS FILE.
    @AUTHOR 
      CJLAI
    """

    _SOURCE_PROFILE_NAME ='xx'
    _SOURCE_USER_NAME = 'xxxxxx'
    _MFA_DEVICES_TYPE = 'google_authenticator'
    _MFA_TOKEN_CODE = 'xxxxx'

    # 1. 透過SOURCE_PROFILE_NAME建立clinet session
    init_session = boto3.Session(profile_name=_SOURCE_PROFILE_NAME)
    iam_clinet = init_session.client('iam')    

    # 2. 取得SOURCE_USER_NAME的mfa devices判斷是否為MFA_DEVICES_TYPE
    response = iam_clinet.list_mfa_devices(UserName=_SOURCE_USER_NAME)
    for obj in response.get('MFADevices'): 
        if re.search(_MFA_DEVICES_TYPE, obj['SerialNumber']):
            _serial_number= obj['SerialNumber']
    
    # 3. 輸入MFA_TOKEN_CODE取得temporary credentials            
    sts_client = init_session.client('sts')    
    sts_response = sts_client.get_session_token(
        SerialNumber=_serial_number,
        TokenCode=_MFA_TOKEN_CODE
    )
    credentials_info = sts_response.get('Credentials')

    # 4. 輸出aws shared credentials file需要寫入的內容
    print('[session]')
    print('aws_access_key_id = ' + credentials_info.get('AccessKeyId'))
    print('aws_secret_access_key = ' + credentials_info.get('SecretAccessKey'))
    print('aws_session_token=' + credentials_info.get('SessionToken'))
    
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    main()