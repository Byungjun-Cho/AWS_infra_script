#!/bin/bash

export PATH=$PATH:/usr/local/bin:/usr/bin:/bin

# OS 유형 확인 (Debian/Ubuntu vs. RedHat 계열)
OS_TYPE=""
if type lsb_release >/dev/null 2>&1; then
    OS_TYPE=$(lsb_release -si)
elif [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_TYPE=$ID
fi
OS_TYPE=$(echo "$OS_TYPE" | tr '[:upper:]' '[:lower:]') # 소문자로 변환

echo "Detected OS: $OS_TYPE"


# --- AWS CLI v2 설치 (아키텍처 구분) ---
if command -v aws &> /dev/null; then
    echo "AWS CLI is already installed at $(command -v aws). Skipping installation."
else
    ARCH=$(uname -m)
    AWS_CLI_ZIP_URL=""
    if [[ "$ARCH" == "x86_64" ]]; then
        AWS_CLI_ZIP_URL="https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip"
        echo "Detected x86_64 architecture. Downloading x86_64 AWS CLI."
    elif [[ "$ARCH" == "aarch64" ]]; then
        AWS_CLI_ZIP_URL="https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip"
        echo "Detected aarch64 (ARM) architecture. Downloading ARM64 AWS CLI."
    else
        echo "Unsupported architecture: $ARCH. Cannot download AWS CLI." >&2
        exit 1
    fi

    echo "Installing AWS CLI v2 from $AWS_CLI_ZIP_URL..."

    # curl 대신 AWS_CLI 설치 방법 고민중
    curl -sS "$AWS_CLI_ZIP_URL" -o "awscliv2.zip"

    # unzip 없을 경우 설치하는 코드 추가 예정
    unzip awscliv2.zip
    sudo ./aws/install --update
    rm -rf awscliv2.zip aws/
fi
# --- AWS CLI 설치 끝 ---


# S3 스크립트 다운로드, 실행 및 결과 파일 S3 업로드
SCRIPT_PATH="/tmp/test_shell.sh"
S3_DOWNLOAD_PATH="s3://security-infra-script/test_shell.sh"
S3_UPLOAD_BUCKET_PATH="s3://security-infra-script/" # 결과 파일을 업로드할 S3 버킷/폴더 경로

# 호스트명 파일 생성
# (한 계정 내 호스트명이 중복일 경우가 있는지 확인 필요)
RESULT_FILE_NAME="$(hostname)-result.json"
echo "Dynamically set result file name to: $RESULT_FILE_NAME"

echo "Downloading script from S3: $S3_DOWNLOAD_PATH"
aws s3 cp "$S3_DOWNLOAD_PATH" "$SCRIPT_PATH"

if [ $? -eq 0 ]; then
    echo "Script downloaded successfully. Setting execution permissions."
    chmod +x "$SCRIPT_PATH"
    echo "Executing the script..."
    
    # 다운로드한 스크립트 실행
    "$SCRIPT_PATH"
    SCRIPT_EXIT_CODE=$?
    echo "Script execution finished with exit code: $SCRIPT_EXIT_CODE"

    # --- 결과 파일 S3 업로드 시작 ---
    if [ -f "$RESULT_FILE_NAME" ]; then
        echo "Result file '$RESULT_FILE_NAME' found. Uploading to S3."
        aws s3 cp "$RESULT_FILE_NAME" "$S3_UPLOAD_BUCKET_PATH$RESULT_FILE_NAME"
        
        if [ $? -eq 0 ]; then
            echo "Successfully uploaded result file to $S3_UPLOAD_BUCKET_PATH$RESULT_FILE_NAME"
            rm -f "$RESULT_FILE_NAME"
        else
            echo "Failed to upload result file to S3." >&2
        fi
    else
        echo "Result file '$RESULT_FILE_NAME' not found. Skipping upload."
    fi
    # --- 결과 파일 S3 업로드 끝 ---

    rm -f "$SCRIPT_PATH"
    exit $SCRIPT_EXIT_CODE
else
    echo "Failed to download script from S3. Exiting." >&2
    exit 1
fi