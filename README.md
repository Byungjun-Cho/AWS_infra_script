# AWS 인프라 자동화 진단 

## 개요

중앙 AWS 계정의 Lambda 함수가 여러 대상 계정의 EC2 인스턴스를 자동으로 점검하고, 결과를 S3에 취합하는 프로젝트입니다. 배포는 GitHub Actions를 통해 자동화됩니다.

---
## 주요 기능

* **다중 계정 지원**: 여러 AWS 계정을 동시에 점검합니다.
* **동적 인스턴스 탐색**: 태그 기반으로 점검 대상을 자동으로 찾습니다.
* **안전한 권한 사용**: IAM 역할 전환(AssumeRole)으로 각 계정에 접근합니다.
* **배포 자동화**: `main` 브랜치에 Push하면 GitHub Actions가 자동으로 Lambda에 배포합니다.

---
## 설정 체크리스트

이 프로젝트를 실행하려면 아래 AWS 리소스가 미리 준비되어야 합니다.

* **중앙 계정**:
    * 대상 계정의 역할을 수임(`sts:AssumeRole`)할 수 있는 **Lambda 실행 역할**
    * GitHub Actions가 Lambda를 배포할 때 사용할 **OIDC용 IAM 역할**
* **대상 계정 (모든 점검 계정)**:
    * SSM 명령어 실행(`ssm:SendCommand`)과 인스턴스 조회(`ec2:DescribeInstances`) 권한을 가진 **`InfraVulnCheckSSMRole` 역할** (Lambda가 수임하도록 신뢰 관계 설정 필요)
    * S3 접근 권한을 가진 **EC2 인스턴스 프로파일 역할**
    * 점검 대상 인스턴스에 식별용 **태그** 부착
* **S3 버킷**:
    * 실행할 점검 스크립트(`test_shell.sh`) 업로드
    * 결과를 저장할 폴더 준비

---
## 설정 및 사용법

### 1. Lambda 환경 변수 설정

* `TARGET_ACCOUNT_IDS`: 콤마로 구분된 점검 대상 AWS 계정 ID 목록
* `ROLE_TO_ASSUME_NAME`: 대상 계정에서 수임할 역할 이름
* `S3_BUCKET_PATH`: 결과 파일을 저장할 S3 경로

### 2. 실행

* **수동 실행 (AWS CLI)**
    ```bash
    aws lambda invoke --function-name Infra_security_function --profile infra-check response.json
    ```
* **자동 실행 (Amazon EventBridge)**
    * Lambda 콘솔의 `트리거 추가` 메뉴에서 EventBridge를 선택하고, 원하는 실행 주기를 설정합니다.

---
### 📂 프로젝트 구조

```text
.
├── .github/
│   └── workflows/
│       └── deploy.yml
├── lambda_function.py
├── run_command.sh
└── README.md