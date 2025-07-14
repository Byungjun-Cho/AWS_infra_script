import boto3
import os

# 쉘 스크립트를 별도 파일에서 읽어오도록 수정
with open('run_command.sh', 'r') as f:
    RUN_COMMAND_SCRIPT = f.read()

# 환경 변수에서 설정값 가져오기
TARGET_ACCOUNT_IDS_STR = os.environ['TARGET_ACCOUNT_IDS']
ROLE_TO_ASSUME_NAME = os.environ['ROLE_TO_ASSUME_NAME']


# 계정ID 기입 (콤마로 구분)
TARGET_ACCOUNT_IDS = [acc_id.strip() for acc_id in TARGET_ACCOUNT_IDS_STR.split(',')]

def lambda_handler(event, context):
    sts_client = boto3.client('sts')
    
    # 모든 대상 계정을 순회하는 루프
    for account_id in TARGET_ACCOUNT_IDS:
        print(f"--- Processing Account: {account_id} ---")
        
        try:
            # 1. 각 계정의 역할 수임
            role_arn = f"arn:aws:iam::{account_id}:role/{ROLE_TO_ASSUME_NAME}"
            assumed_role_object = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=f"SecurityCheckSession-{account_id}"
            )
            credentials = assumed_role_object['Credentials']

            # 2. 임시 자격 증명을 파라미터 이름으로 전달하여 클라이언트 생성
            region = os.environ.get('AWS_REGION', 'ap-northeast-2')
            
            ec2_client = boto3.client(
                'ec2',
                region_name=region,
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
            ssm_client = boto3.client(
                'ssm',
                region_name=region,
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )

            # 3. 태그를 기준으로 인스턴스 동적 조회
            target_instances = []
            paginator = ec2_client.get_paginator('describe_instances')
            pages = paginator.paginate(
                Filters=[
                    {'Name': 'instance-state-name', 'Values': ['running']},
                    # 사용할 태그를 지정 - 생성 예정 태그 'Name': 'tag:security', 'Value': ['infra']
                    {'Name': 'tag:domain', 'Values': ['security']}
                ]
            )
            for page in pages:
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        target_instances.append(instance['InstanceId'])

            if not target_instances:
                print(f"No instances found with the specified tags in account {account_id}. Skipping.")
                continue

            print(f"Found {len(target_instances)} instances to scan: {target_instances}")

            # 4. S3 업로드 
            s3_upload_path_for_account = "s3://security-infra-script/"
            
            response = ssm_client.send_command(
                InstanceIds=target_instances,
                DocumentName='AWS-RunShellScript',
                Parameters={
                    'commands': [
                        f"export S3_UPLOAD_PATH_PER_ACCOUNT='{s3_upload_path_for_account}'",
                        RUN_COMMAND_SCRIPT
                    ]
                },
                Comment=f'Automated security check for account {account_id}'
            )
            
            command_id = response['Command']['CommandId']
            print(f"Successfully sent command to account {account_id}. Command ID: {command_id}")

        except Exception as e:
            print(f"[ERROR] Failed to process account {account_id}. Reason: {e}")
            continue
            
    return {'statusCode': 200, 'body': 'All accounts processed.'}