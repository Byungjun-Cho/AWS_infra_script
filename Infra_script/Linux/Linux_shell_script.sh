#!/bin/bash

### Variables ###
HOSTNAME=$(hostname)
LANG=C
export LANG
clear

if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "sudo $0 $*"
    exit 1
fi

if type lsb_release >/dev/null 2>&1; then
    # linuxbase.org
    OS=$(lsb_release -si)
    VER=$(lsb_release -sr)
elif [ -f /etc/lsb-release ]; then
    # For some versions of Debian/Ubuntu without lsb_release command
    . /etc/lsb-release
    OS=$DISTRIB_ID
    VER=$DISTRIB_RELEASE
elif [ -f /etc/redhat-release ] ; then
    OS='RedHat'
    VER=''
elif [ -f /etc/debian_version ]; then
    # Older Debian/Ubuntu/etc.
    OS='Debian'
    VER=$(cat /etc/debian_version)
else
    # Fall back to uname, e.g. "Linux <version>", also works for BSD, etc.
    OS=$(uname -s)
    VER=$(uname -r)
fi

#-----------------------수정 시작 부분 입니다!--------------------------
tmp_file="$HOSTNAME-result.json"
start_time=$(date +%s)
echo "[]" > $tmp_file

# OS를 감지하여 jq 설치
echo "Installing jq using system package manager..."
if command -v apt-get &>/dev/null; then
    # Debian/Ubuntu
    sudo apt-get update -y
    sudo apt-get install -y jq
elif command -v yum &>/dev/null; then
    # Amazon Linux, CentOS, RHEL
    sudo yum install -y jq
else
    echo "Could not find apt-get or yum. Please install jq manually." >&2
    exit 1
fi

echo "jq installed successfully."


write_result() {
    id=$1
    description=$2
    check=$3
    duration=$4
    result=$5

    echo $id, $description, $check, $duration
    item=$(jq -n --arg id "$id" --arg description "$description" --arg check "$check" --arg duration "$duration" --arg result "$result" '$ARGS.named' | sed 's/\\\\n/\n/g')

    cat $tmp_file | jq ". += [$item]" > tmp.json #수정 ./jq에서 jq로
    mv tmp.json $tmp_file
}

#-----------------------수정 끝 부분 입니다!--------------------------

now() {
    echo $(( $(date +%s%N) / 1000000 ))
}

test_start() {
    now
}

test_finish() {
    id=$1
    start_time=$2
    echo "$(( $(now) - $start_time ))"
} 

test_U_01() {
    id="U-01"
    check="Y"
    description="root 계정 원격 접속 제한"
    start_time=$(test_start $id)
    result="■ 기준: 원격 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 차단한 경우 양호
        /etc/securetty 파일에 pts/* 설정이 있으면 무조건 취약
        /etc/securetty 파일에 pts/* 설정이 없거나 주석처리가 되어 있고,
        /etc/pam.d/login에서 auth required /lib/security/pam_securetty.so 라인에 주석(#)이 없으면 양호
        /etc/ssh/sshd_config에 PermitRootLogin가 no인 경우 양호" \
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    # check Telnet service
    result=$result"Telnet Service\n"
    result=$result"-----------------------\n"
    if [[ `((systemctl --type=service --state=running 2>/dev/null) || (service --status-all 2>/dev/null | egrep 'running|enabled' )) | egrep "telnet" | wc -l` -gt 0 ]]; then
        result=$result`((systemctl --type=service --state=running 2>/dev/null) || (service --status-all 2>/dev/null | egrep 'running|enabled' )) | egrep "telnet"`
        result=$result`(netstat -lap 2>/dev/null || ss -lap 2>/dev/null) | grep ":telnet"`
        check="N"
    else
        result=$result"Telnet Service Disable\n\n"
    fi


    # check /etc/securitty
    result=$result"/etc/securetty\n"
    result=$result"-----------------------\n"
    if [ -f /etc/securetty ]; then
        if [ `cat /etc/securetty | egrep -v "^\s*(#|$)" | grep "pts" | grep -v "Concepts"| wc -l` -gt 0 ]; then
            result=$result$(cat /etc/securetty | grep "pts")"\n\n"
            check="N"
        else
            result=$result"/etc/securetty 파일에 pts/0~pts/x 설정이 없습니다.\n\n"

            #check /etc/pam.d/login
            result=$result"/etc/pam.d/login\n"
            if [ -f /etc/pam.d/login ]; then
                if [ `cat /etc/pam.d/login | egrep -v "^\s*(#|$)" | grep "pam_securetty.so" | wc -l` -gt 0 ]; then
                    result=$result`cat /etc/pam.d/login | egrep -v "^\s*(#|$)" | grep "pam_securetty.so"`"\n\n"
                else
                    result=$result"/etc/securetty 파일에 pts/0~pts/x 설정이 없습니다.\n\n"
                    check="N"
                fi
            else
                result=$result"/etc/pam.d/login 파일없음\n\n"
            fi
        fi
    else
        result=$result"/etc/securetty 파일없음\n\n"
    fi

    # check /etc/ssh/sshd_config 
    result=$result"/etc/ssh/sshd_config\n"
    result=$result"-----------------------\n"
    if [ -f /etc/ssh/sshd_config ]; then
        result=$result`cat /etc/ssh/sshd_config | egrep 'PermitRootLogin'`"\n"
        if [ `cat /etc/ssh/sshd_config | egrep -v "^\s*(#|$)" | egrep -is '^\s*PermitRootLogin' | grep -v "no" | wc -l` -gt 0 ]; then
            check="N"
        fi
    else
        result=$result"/etc/ssh/sshd_config 파일 없음.\n"
    fi

    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 


test_U_02() {
    id="U-02"
    check="Y"
    description="패스워드 복잡성 설정"
    start_time=$(test_start $id)
    result="■ 기준: 영문,숫자,특수문자가 혼합된 8자리 이상의 패스워드가 설정된 경우 양호
            ■ 참고: credit 값 = u:대문자, l:소문자, d: 숫자, o:숫자/영문자를 제외한 기타문자"
    result=$result"\n\n■ 현황\n"

    ## Tests Start ##
    if [ "$OS" == "Ubuntu" ] || [ "$OS" == "Debian" ]; then
        check_file1="/etc/pam.d/common-auth"
        check_file2="/etc/pam.d/common-password"
    else
        check_file1="/etc/pam.d/system-auth"
        check_file2="/etc/pam.d/password-auth"
    fi

    # file1 check
    if [ -f $check_file1 ]; then
        result=$result"$check_file1\n"
        result=$result"-----------------------\n"
        result=$result`cat $check_file1 | egrep "pam_pwquality|pam_cracklib"`"\n\n"

        if [ `cat $check_file1 | egrep -v "^\s*(#|$)" | egrep "pam_pwquality|pam_cracklib" | wc -l` -gt 0 ]; then    
            tmp=`cat $check_file1 | egrep -v "^\s*(#|$)" | egrep "pam_pwquality|pam_cracklib"`
            
            if [ `echo $tmp | grep ucredit | wc -l` -lt 1 ]; then
                check="N"
            fi

            if [ `echo $tmp | grep lcredit | wc -l` -lt 1 ]; then
                check="N"
            fi

            if [ `echo $tmp | grep dcredit | wc -l` -lt 1 ]; then
                check="N"
            fi

            if [ `echo $tmp | grep ocredit | wc -l` -lt 1 ]; then
                check="N"
            fi

            if [ `echo $tmp | grep minclass | wc -l` -gt 0 ]; then
                check="Y"
            fi
        fi
    else
        result=$result"$check_file1 파일 없음\n"
    fi

    # file2 check
    if [ -f $check_file2 ]; then
        result=$result"$check_file2\n"
        result=$result"-----------------------\n"
        result=$result`cat $check_file2 | egrep "pam_pwquality|pam_cracklib"`"\n\n"

        if [ `cat $check_file2 | egrep -v "^\s*(#|$)" | egrep "pam_pwquality|pam_cracklib" | wc -l` -gt 0 ]; then
            tmp=`cat $check_file2 | egrep -v "^\s*(#|$)" | egrep "pam_pwquality|pam_cracklib"`
            if [ `echo $tmp | grep ucredit | wc -l` -lt 1 ]; then
                check="N"
            fi

            if [ `echo $tmp | grep lcredit | wc -l` -lt 1 ]; then
                check="N"
            fi

            if [ `echo $tmp | grep dcredit | wc -l` -lt 1 ]; then
                check="N"
            fi

            if [ `echo $tmp | grep ocredit | wc -l` -lt 1 ]; then
                check="N"
            fi

            if [ `echo $tmp | grep minclass | wc -l` -gt 0 ]; then
                check="Y"
            fi
        fi
    else
        result=$result"$check_file2 파일 없음\n"
    fi

    if [ -f /etc/pam.d/sshd ]; then
        # Google OTP use
        result=$result"OTP 사용 여부\n"
        result=$result"-----------------------\n"
        result=$result`cat /etc/pam.d/sshd | egrep -v "^\s*(#|$)" | grep "pam_google_authenticator.so"`"\n\n"

        if [ `cat /etc/pam.d/sshd | egrep -v "^\s*(#|$)" | grep "pam_google_authenticator.so" | wc -l` -gt 0 ]; then
            if [ `cat /etc/ssh/sshd_config | egrep -v "^\s*(#|$)" | grep "^\s*PasswordAuthentication\s*no" | wc -l` -gt 0 ]; then
                check="Y"
                result=$result"OTP 사용 중\n"
            else
                result=$result"OTP 미사용"
            fi
        else
            result=$result"OTP 미사용"
        fi    
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_03(){
    id="U-03"
    check="Y"
    description="계정 잠금 임계값 설정"
    start_time=$(test_start $id)
    result="■ 기준: 계정 잠금 임계값이 5 이하의 값으로 설정되어 있는 경우 양호
    ■       /etc/pam.d/system-auth 파일에 아래와 같은 설정이 있으면 양호
    ■       (auth required /lib/security/pam_tally.so deny=5 unlock_time=120 no_magic_root)
    ■       (account required /lib/security/pam_tally.so no_magic_root reset"
    result=$result"\n\n■ 현황\n"


    ## Tests Start ##
    if [ "$OS" == "Ubuntu" ] || [ "$OS" == "Debian" ]; then
        check_file1="/etc/pam.d/common-auth"
        check_file2="/etc/pam.d/common-password"
    else
        check_file1="/etc/pam.d/system-auth"
        check_file2="/etc/pam.d/password-auth"
    fi

    #check file1
    result=$result"$check_file1\n"
    result=$result"-----------------------\n"
    if [ -f $check_file1 ]; then
        if [ `cat $check_file1 | egrep -v "^\s*(#|$)" | egrep "pam_tally" | wc -l` -gt 0 ]; then
            tmp=`cat $check_file1 | egrep -v "^\s*(#|$)" | egrep "pam_tally" | sed -e "s/\s/\n/g"`
            result=$result`cat $check_file1 | egrep -v "^\s*(#|$)" | egrep "pam_tally"`"\n"
            if [ `echo $tmp | egrep "deny" | wc -l` -eq 0 ]; then
                check="N"
            else
                if [ `echo $tmp | egrep "deny" | awk -F'=' '{print $2}'` -gt 5 ]; then
                    check="N"
                fi
            fi
        fi
    else
        result=$result"$check_file1 파일 없음\n"
    fi

    #check file2
    result=$result"\n$check_file2\n"
    result=$result"-----------------------\n"
    if [ -f $check_file2 ]; then
        if [ `cat $check_file2 | egrep -v "^\s*(#|$)" | egrep "pam_tally" | wc -l` -gt 0 ]; then
            tmp=`cat $check_file2 | egrep -v "^\s*(#|$)" | egrep "pam_tally" | sed -e "s/\s/\n/g"`
            result=$result`cat $check_file2 | egrep -v "^\s*(#|$)" | egrep "pam_tally"`
            if [ `echo $tmp | egrep "deny" | wc -l` -eq 0 ]; then
                check="N"
            else
                if [ `echo $tmp | egrep "deny" | awk -F'=' '{print $2}'` -gt 5 ]; then
                    check="N"
                fi
            fi
        fi
    else
        result=$result"$check_file2 파일 없음\n"
    fi

    if [ "$OS" == "Ubuntu" ] || [ "$OS" == "Debian" ]; then
        if [[ -f "/etc/login.defs" ]]; then
            local threshold=$(grep -E "^PASS_MAX_DAYS" "/etc/login.defs" | awk '{print $2}')
            if [[ "$threshold" -le 5 ]]; then
                result+="[양호] 잠금 임계값 설정: $threshold\n"
                check="Y"
            else
                result+="[취약] 잠금 임계값 설정: $threshold\n"
                check="N"
            fi
        else
            result+="[오류] /etc/login.defs 파일을 찾을 수 없습니다.\n"
        fi
    fi

    if [ -f /etc/pam.d/sshd ]; then
        # Google OTP use
        result=$result"\nOTP 사용 여부\n"
        result=$result"-----------------------\n"
        if [ `cat /etc/pam.d/sshd | egrep -v "^\s*(#|$)" | grep "pam_google_authenticator.so" | wc -l` -gt 0 ]; then
            if [ `cat /etc/ssh/sshd_config | egrep -v "^\s*(#|$)" | grep "^\s*PasswordAuthentication\s*no" | wc -l` -gt 0 ]; then
                check="Y"
                result=$result"OTP 사용 중\n"
            else
                result=$result"OTP 미사용"
            fi
        else
            result=$result"OTP 미사용"
        fi    
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_04(){
    id="U-04"
    check="Y"
    description="패스워드 파일 보호"
    start_time=$(test_start $id)
    result="■ 기준: 패스워드가 /etc/shadow 파일에 암호화 되어 저장되고 있으면 양호"
    result=$result"\n\n■ 현황\n"

    ## Tests Start ##
    result=$result"/etc/passwd\n"
    result=$result"-----------------------\n"
    if [ -f /etc/passwd ]; then
        result=$result$(cat /etc/passwd | head -n 5)"\n\n"
        if [ `awk -F: '$2=="x"' /etc/passwd | wc -l` -eq 0 ]; then
            check="N"
        fi
    else
        check="-"
        echo "☞ /etc/passwd 파일이 없습니다.\n\n"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_05() {
    id="U-05"
    check="Y"
    description="root 홈, 패스 디렉터리 권한 및 패스 설정"
    start_time=$(test_start $id)
    result="■ 기준: Path 설정에 \".\" 이 맨 앞이나 중간에 포함되어 있지 않을 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    result=$result"\$PATH: ${PATH}\n\n"
    if [ `echo $PATH | grep "\.:" | wc -l` -eq 0 ]; then
        result=$result"Path 설정에 '.'이 포함되지 않음.\n"
    else
        check="N"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_06() {
    id="U-06"
    check="Y"
    description="파일 및 디렉터리 소유자 설정"
    start_time=$(test_start $id)
    result="■ 기준: 소유자가 존재하지 않은 파일 및 디렉토리가 존재하지 않을 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    result=$result"소유자가 존재하지 않는 파일\n"
    result=$result"-----------------------\n"
    if [ `find / -nouser 2>/dev/null | egrep -v "/proc|/var/cache|/var/lib/|chrony" | wc -l` -gt 0 ]; then
        check="N"
    else
        result=$result"소유자가 존재하지 않는 파일이 발견되지 않았습니다.\n"
    fi    
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 


test_U_07() {
    id="U-07"
    check="Y"
    description="/etc/passwd 파일 소유자 및 권한 설정"
    start_time=$(test_start $id)
    result="■ 기준: /etc/passwd 파일의 소유자가 root 이고, 권한이 644 이하인 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ -f /etc/passwd ]; then
        result=$result`ls -l /etc/passwd`
        if [ `stat -c "%a" /etc/passwd` -gt 644 ] || [ `stat -c "%U" /etc/passwd` != 'root' ]; then
            check="N"
        fi
    else
        result=$result"/etc/passwd 파일이 없습니다."
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_08() {
    id="U-08"
    check="Y"
    description="/etc/shadow 파일 소유자 및 권한 설정"
    start_time=$(test_start $id)
    result="■ 기준: /etc/shadow 파일의 소유자가 root 이고, 권한이 400 이하인 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ -f /etc/shadow ]; then
        result=$result`ls -l /etc/shadow`
        if [ `stat -c "%a" /etc/shadow` -gt 400 ] || [ `stat -c "%U" /etc/shadow` != 'root' ]; then
            check="N"
        fi
    else
        result=$result"/etc/shadow 파일이 없습니다."
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_09() {
    id="U-09"
    check="Y"
    description="/etc/hosts 파일 소유자 및 권한 설정"
    start_time=$(test_start $id)
    result="■ 기준: /etc/hosts 파일의 소유자가 root 이고, 권한이 600 이하인 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ -f /etc/hosts ]; then
        result=$result`ls -l /etc/hosts`
        if [ `stat -c "%a" /etc/hosts` -gt 600 ] || [ `stat -c "%U" /etc/hosts` != 'root' ]; then
            check="N"
        fi
    else
        result=$result"/etc/hosts 파일이 없습니다."
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_10() {
    id="U-10"
    check="Y"
    description="/etc/(x)inetd.conf 파일 소유자 및 권한 설정"
    start_time=$(test_start $id)
    result="■ 기준: /etc/(x)inetd.conf 파일 및 /etc/xinetd.d/ 하위 모든 파일의 소유자가 root 이고, 권한이 600 이하인 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    result=$result"/etc/xinetd.conf\n"
    result=$result"----------------------------------\n"
    if [ -f /etc/xinetd.conf ]; then
        result=$result`ls -al /etc/xinetd.conf`
        if [ `stat -c "%a" /etc/xinetd.conf` -gt 600 ] || [ `stat -c "%U" /etc/xinetd.conf` != 'root' ]; then
            check="N"
        fi
    else
        result=$result"/etc/xinetd.conf 파일이 없습니다."
    fi

    result=$result"\n\n"
    result=$result"/etc/xinetd.d/\n"
    result=$result"----------------------------------\n"
    if [ -d /etc/xinetd.d ]; then
        result=$result`ls -ld /etc/xinetd.d`"\n"
        result=$result`ls -al /etc/xinetd.d/*`

        for file in `ls /etc/xinetd.d/*`
        do
            if [ `stat -c "%a" ${file}` -gt 600 ] || [ `stat -c "%U" ${file}` != 'root' ]; then
                check="N"
            fi
        done
    else
        result=$result"/etc/xinetd.d 디렉터리가 없습니다."
    fi
    
    result=$result"\n\n"
    result=$result"/etc/inetd.conf\n"
    result=$result"----------------------------------\n"
    if [ -f /etc/inetd.conf ]; then
        result=$result`ls -al /etc/inetd.conf`
        if [ `stat -c "%a" /etc/inetd.conf` -gt 600 ] || [ `stat -c "%U" /etc/inetd.conf` != 'root' ]; then
            check="N"
        fi
    else
        result=$result"/etc/inetd.conf 파일이 없습니다."
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_11() {
    id="U-11"
    check="Y"
    description="/etc/syslog.conf 파일 소유자 및 권한 설정"
    start_time=$(test_start $id)
    result="■ 기준: /etc/syslog.conf 파일의 권한이 644 이하인 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ -f /etc/syslog.conf ]; then
        result=$result"/etc/syslog.conf\n"
        result=$result"-----------------------\n"
        result=$result`ls -l /etc/syslog.conf`
        if [ `stat -c "%a" /etc/syslog.conf` -gt 644 ] || [ `stat -c "%U" /etc/syslog.conf` != 'root' ]; then
            check="N"
        fi
    else
        result=$result"/etc/syslog.conf 파일이 없습니다.\n"
    fi

    if [ -f /etc/rsyslog.conf ]; then
        result=$result"\n/etc/rsyslog.conf\n"
        result=$result"-----------------------\n"
        result=$result`ls -l /etc/rsyslog.conf`
        if [ `stat -c "%a" /etc/rsyslog.conf` -gt 644 ] || [ `stat -c "%U" /etc/rsyslog.conf` != 'root' ]; then
            check="N"
        fi
    else
        result=$result"/etc/rsyslog.conf 파일이 없습니다."
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_12() {
    id="U-12"
    check="Y"
    description="/etc/services 파일 소유자 및 권한 설정"
    start_time=$(test_start $id)
    result="■ 기준: /etc/services 파일의 권한이 644 이하인 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    result=$result"/etc/services\n"
    result=$result"-----------------------\n"
    if [ -f /etc/services ]; then
        result=$result`ls -l /etc/services`
        if [ `stat -c "%a" /etc/services` -gt 644 ] || [ `stat -c "%U" /etc/services` != 'root' ]; then
            check="N"
        fi
    else
        result=$result"/etc/services 파일이 없습니다."
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_13() {
    id="U-13"
    check="Y"
    description="SUID, SGID, Sticky bit 설정 파일 점검"
    start_time=$(test_start $id)
    result="■ 기준: 불필요한 SUID/SGID 설정이 존재하지 않을 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    check_file="/sbin/dump /usr/bin/lpq-lpd /usr/bin/newgrp /sbin/restore /usr/bin/lpr /usr/sbin/lpc /sbin/unix_chkpwd /usr/bin/lpr-lpd /usr/sbin/lpc-lpd /usr/bin/at /usr/bin/lprm /usr/sbin/traceroute /usr/bin/lpq /usr/bin/lprm-lpd"
    for file in $check_file
    do
        if [ -f $file ]; then
            if [ `stat -c "%a" $file` -gt 1000 ]; then
                result=$result`ls -l ${file}`"\n"
                check="N"
            fi
        fi
    done
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_14() {
    id="U-14"
    check="Y"
    description="사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정"
    start_time=$(test_start $id)
    result="■ 기준: 홈디렉터리 환경변수 파일에 타사용자 쓰기 권한이 제거되어 있으면 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    FILES=".profile .cshrc .kshrc .login .bash_profile .bashrc .bash_login .exrc .netrc .history .sh_history .bash_history .dtprofile"

    result=$result"홈디렉터리 환경변수 파일\n"
    result=$result"-----------------------\n"
    for USER_INFO in `egrep "bin/.*sh" /etc/passwd`
    do
        OWNER=`echo $USER_INFO | awk -F: '{print $1}'`
        HOME=`echo $USER_INFO | awk -F: '{print $6}'`
        for FILE in $FILES
        do
            FILE=$HOME/$FILE
            if [ -f $FILE ]; then
                result=$result`ls -alL $FILE`"\n"
                if [ `stat -c "%U" $FILE` != $OWNER ] && [ `ls -l $FILE | egrep "........w." | wc -l` -gt 0 ]; then
                    check="N"
                fi
            fi
        done
    done
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_15() {
    id="U-15"
    check="Y"
    description="world writable 파일 점검"
    start_time=$(test_start $id)
    result="■ 기준: 불필요한 권한이 부여된 world writable 파일이 존재하지 않을 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    result=$result"World Writable 파일 점검(/etc,/home,/tmp,/var)\n"
    result=$result"-----------------------\n"
    if [ `find /tmp -type f -perm -2 -ls | awk '{print $3 "  :  " $5 "  :  " $6 "  :  " $11}' | grep -v ^l | wc -l` -gt 0 ]; then
        result=$result`find /tmp -type f -perm -2 -ls | awk '{print $3 "  :  " $5 "  :  " $6 "  :  " $11}' | grep -v ^l`
        check="N"
    fi

    if [ `find /home -type f -perm -2 -ls | awk '{print $3 "  :  " $5 "  :  " $6 "  :  " $11}' | grep -v ^l | wc -l` -gt 0 ]; then
        result=$result`find /home -type f -perm -2 -ls | awk '{print $3 "  :  " $5 "  :  " $6 "  :  " $11}' | grep -v ^l`
        check="N"
    fi

    if [ `find /etc -type f -perm -2 -ls | awk '{print $3 "  :  " $5 "  :  " $6 "  :  " $11}' | grep -v ^l | wc -l` -gt 0 ]; then
        result=$result`find /etc -type f -perm -2 -ls | awk '{print $3 "  :  " $5 "  :  " $6 "  :  " $11}' | grep -v ^l`
        check="N"
    fi

    if [ `find /var -type f -perm -2 -ls | awk '{print $3 "  :  " $5 "  :  " $6 "  :  " $11}' | egrep -v "^l|cgroup" | wc -l` -gt 0 ]; then
        result=$result`find /var -type f -perm -2 -ls | awk '{print $3 "  :  " $5 "  :  " $6 "  :  " $11}' | grep -v ^l`
        check="N"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_16() {
    id="U-16"
    check="Y"
    description="/dev에 존재하지 않는 device 파일 점검"
    start_time=$(test_start $id)
    result="■ 기준 : dev 에 존재하지 않은 Device 파일을 점검하고, 존재하지 않은 Device을 제거 했을 경우 양호
            ■     : (아래 나열된 결과는 major, minor Number를 갖지 않는 파일임)
            ■     : (.devlink_db_lock/.devfsadm_daemon.lock/.devfsadm_synch_door/.devlink_db는 Default로 존재 예외)"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    result=$result"dev에 존재하지 않는 Device 파일\n"
    result=$result"-----------------------\n"
    if [ `find /dev -type f -exec ls -l {} \; | egrep -v "\.udev|\.devlink|\.devfsadm|\/dev\/shm" | wc -l` -gt 0 ]; then
        result=$result`find /dev -type f -exec ls -l {} \; | egrep -v "\.udev|\.devlink|\.devfsadm|\/dev\/shm"`
        check="N"
    else
        result=$result"dev 에 존재하지 않은 Device 파일이 발견되지 않았습니다."
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_17() {    
    id="U-17"
    check="Y"
    description="$HOME/.rhosts, hosts.equiv 사용 금지"
    start_time=$(test_start $id)
    result="■ 기준: r-commands 서비스를 사용하지 않으면 양호
            ■     : r-commands 서비스를 사용하는 경우 HOME/.rhosts, hosts.equiv 설정확인
            ■     : (1) .rhosts 파일의 소유자가 해당 계정의 소유자이고, 퍼미션 600, 내용에 + 가 설정되어 있지 않으면 양호
            ■     : (2) /etc/hosts.equiv 파일의 소유자가 root 이고, 퍼미션 600, 내용에 + 가 설정되어 있지 않으면 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    result=$result"/etc/hosts.equiv 파일 설정\n"
    result=$result"-----------------------\n"
    if [ -f /etc/hosts.equiv ]; then
            if [ `cat /etc/hosts.equiv | egrep -v '^\s*(#|$)' | wc -l` -gt 0 ]; then
                result=$result`cat /etc/hosts.equiv | egrep -v '^\s*(#|$)'`
                check="N"
            else
                result=$result"설정 내용이 없습니다.\n"
            fi
        else
            result=$result"/etc/hosts.equiv 파일이 없습니다."
    fi

    result=$result"\n\n"
    result=$result"사용자 home directory .rhosts 설정 내용\n"
    result=$result"-----------------------\n"


    for HOME in `egrep "bin/.*sh" /etc/passwd | awk -F: '{print $6}'`
    do
        FILE=$HOME"/.rhosts"
        if [ -f $FILE ]; then
            result=$result`ls -alL $FILE`
            if [ `stat -c "%U" $FILE` != $OWNER ] && [ `ls -l $FILE | egrep "........w." | wc -l` -gt 0 ]; then
                check="N"
            fi
        else
            result=$result"$FILE가 존재하지 않습니다.\n"
        fi
    done
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_18() {
    id="U-18"
    check="-"
    description="접속 IP 및 포트 제한"
    start_time=$(test_start $id)
    result="■ 기준: /etc/hosts.deny 파일에 All Deny(ALL:ALL) 설정이 등록되어 있고,
            ■    : /etc/hosts.allow 파일에 접근 허용 IP가 등록되어 있으면 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    result=$result"/etc/hosts.allow 파일 설정\n"
    result=$result"-----------------------\n"
    if [ -f /etc/hosts.allow ]; then
        if [ ! `cat /etc/hosts.allow | egrep -v "^\s*(#|$)" | wc -l` -eq 0 ]; then
            result=$result`cat /etc/hosts.allow | egrep -v "^\s*(#|$)"`
        else
            result=$result"설정 내용이 없습니다."
        fi
    else
        result=$result"/etc/hosts.allow 파일이 없습니다."
    fi
    

    result=$result"\n\n/etc/hosts.deny 파일 설정\n"
    result=$result"-----------------------\n"
    if [ -f /etc/hosts.deny ]; then
        if [ ! `cat /etc/hosts.deny | egrep -v "^\s*(#|$)" | wc -l` -eq 0 ]; then
            result=$result`cat /etc/hosts.deny | egrep -v "^\s*(#|$)"`
        else
            result=$result"설정 내용이 없습니다."
            check="N"
        fi
    else
        result=$result"/etc/hosts.deny 파일이 없습니다."
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_19() {
    id="U-19"
    check="Y"
    description="finger 서비스 비활성화"
    start_time=$(test_start $id)
    result="■ 기준: Finger 서비스가 비활성화 되어 있을 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ `(netstat -lap 2>/dev/null || ss -lap 2>/dev/null) | grep :finger | wc -l` -gt 0 ]; then
        result=$result`(netstat -lap 2>/dev/null || ss -lap 2>/dev/null) | grep :finger`
        check="N"
    else
        result=$result"Finger Service Disable"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 


test_U_20() {
    id="U-20"
    check="Y"
    description="Anonymous FTP 비활성화"
    start_time=$(test_start $id)
    result="■ 기준: Anonymous FTP (익명 ftp)를 비활성화 시켰을 경우 양호
            ■    : (1)ftpd를 사용할 경우: /etc/passwd 파일내 FTP 또는 anonymous 계정이 존재하지 않으면 양호
            ■    : (2)proftpd를 사용할 경우: /etc/passwd 파일내 FTP 계정이 존재하지 않으면 양호
            ■    : (3)vsftpd를 사용할 경우: vsftpd.conf 파일에서 anonymous_enable=NO 설정이면 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ `((systemctl --type=service --state=running 2>/dev/null) || (service --status-all 2>/dev/null | egrep "running|enabled" )) | egrep "ftp" | wc -l` -gt 0 ]; then
        result=$result`((systemctl --type=service --state=running 2>/dev/null) || (service --status-all 2>/dev/null | egrep "running|enabled" )) | egrep "ftp"`"\n\n"
        if [ -f /etc/vsftpd.conf ]; then
            result=$result"/etc/vsftpd.conf\n"
            result=$result"-----------------------\n"
            result=$result`cat /etc/vsftpd.conf | grep anonymous_enable`

            if [ `cat /etc/vsftpd.conf | grep anonymous_enable | grep -v NO | wc -l` -gt 0 ]; then
                check="N"
            fi
        else
            result=$result"/etc/passwd\n"
            result=$result"-----------------------\n"
            result=$result`cat /etc/passwd | egrep "ftp|anonymous"`

            if [ `cat /etc/passwd | egrep "ftp|anonymous" | wc -l` -gt 0 ]; then
                check="N"
            fi
        fi
    else
        result=$result"ftp Service Disable"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 


test_U_21() {
    id="U-21"
    check="Y"
    description="r 계열 서비스 비활성화"
    start_time=$(test_start $id)
    result="■ 기준: login, shell, exec 서비스가 구동 중이지 않을 경우
            ■  login, shell, exec 서비스가 구동 중일 경우"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    result=$result"rlogin\n"
    result=$result"-----------------------\n"
    if [ `(netstat -lap 2>/dev/null || ss -lap 2>/dev/null) | grep :login | wc -l` -gt 0 ]; then
        result=$result`(netstat -lap 2>/dev/null || ss -lap 2>/dev/null) | grep :login`
        check="N"
    else
        result=$result"rlogin Service Disable\n"
    fi
    result=$result"\n\nrshell\n"
    result=$result"-----------------------\n"
    if [ `(netstat -lap 2>/dev/null || ss -lap 2>/dev/null) | grep :shell | wc -l` -gt 0 ]; then
        result=$result`(netstat -lap 2>/dev/null || ss -lap 2>/dev/null) | grep :shell`
        check="N"
    else
        result=$result"rshell Service Disable\n"
    fi

    result=$result"\n\nrexec\n"
    result=$result"-----------------------\n"
    if [ `(netstat -lap 2>/dev/null || ss -lap 2>/dev/null) | grep :exec | wc -l` -gt 0 ]; then
        result=$result`(netstat -lap 2>/dev/null || ss -lap 2>/dev/null) | grep :exec`
        check="N"
    else
        result=$result"rexec Service Disable\n"
    fi

    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_22() {
    id="U-22"
    check="Y"
    description="cron 파일 소유자 및 권한 설정"
    start_time=$(test_start $id)
    result="■ 기준: cron 접근제어 파일 소유자가 root이고, 권한이 640 이하인 경우
             cron 접근제어 파일 소유자가 root가 아니거나, 권한이 640 이하가 아닌 경우"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ ! -f /etc/cron.allow ] && [ ! -f /etc/cron.deny ]; then
        result=$result"cron.allow cron.deny 모두없습니다.\n\n"
        check="Y"
    else
        result=$result"cron.allow 파일 권한 확인\n"
        result=$result"-----------------------\n"
        if [ -f /etc/cron.allow ]; then
            result=$result`ls -alL /etc/cron.allow`
            if [ `stat -c "%a" /etc/cron.allow` -gt 640 ]; then
                check="N"
            fi
        else
            result=$result"/etc/cron.allow 파일이 없습니다.\n\n"
        fi
        
        result=$result"cron.deny 파일 권한 확인\n"
        result=$result"-----------------------\n"
        if [ -f /etc/cron.deny ]; then
            result=$result`ls -alL /etc/cron.deny`
            if [ `stat -c "%a" /etc/cron.deny` -gt 640 ]; then
                check="N"
            fi
        else
            result=$result"/etc/cron.deny 파일이 없습니다.\n\n"
        fi
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_23() {
    id="U-23"
    check="Y"
    description="Dos 공격에 취약한 서비스 비활성화"
    start_time=$(test_start $id)
    result="■ 기준: DoS 공격에 취약한 echo , discard , daytime , chargen 서비스를 사용하지 않았을 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    # netstat command exist
    result=$result"echo\n"
    result=$result"-----------------------\n"
    if [ `(netstat -lap 2>/dev/null || ss -lap 2>/dev/null) | grep :echo | wc -l` -gt 0 ]; then
        result=$result`(netstat -lap 2>/dev/null || ss -lap 2>/dev/null) | grep :echo`
        check="N"
    else
        result=$result"echo Service Disable\n"
    fi

    result=$result"\n\ndiscard\n"
    result=$result"-----------------------\n"
    if [ `(netstat -lap 2>/dev/null || ss -lap 2>/dev/null) | grep :discard | wc -l` -gt 0 ]; then
        result=$result`(netstat -lap 2>/dev/null || ss -lap 2>/dev/null) | grep :discard`
        check="N"
    else
        result=$result"discard Service Disable\n"
    fi

    result=$result"\n\ndaytime\n"
    result=$result"-----------------------\n"
    if [ `(netstat -lap 2>/dev/null || ss -lap 2>/dev/null) | grep :daytime | wc -l` -gt 0 ]; then
        result=$result`(netstat -lap 2>/dev/null || ss -lap 2>/dev/null) | grep :daytime`
        check="N"
    else
        result=$result"daytime Service Disable\n"
    fi

    result=$result"\n\nchargen\n"
    result=$result"-----------------------\n"
    if [ `(netstat -lap 2>/dev/null || ss -lap 2>/dev/null) | grep :chargen | wc -l` -gt 0 ]; then
        result=$result`(netstat -lap 2>/dev/null || ss -lap 2>/dev/null) | grep :chargen`
        check="N"
    else
        result=$result"chargen Service Disable\n"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 


test_U_24() {
    id="U-24"
    check="Y"
    description="NFS 서비스 비활성화"
    start_time=$(test_start $id)
    result="■ 기준: NFS 서비스 관련 데몬이 비활성화 되어 있는 경우
             NFS 서비스 관련 데몬이 활성화 되어 있는 경우"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ `ps -ef | grep nfs | egrep -v "grep|statdaemon|automountd|emi" | wc -l` -gt 0 ] ; then
        result=$result`ps -ef | grep nfs | egrep -v "grep|statdaemon|automountd|emi"`
        check="N"
    else
        result=$result"☞ NFS Service Disable"
    fi
    result=$result"\n\n"
    if [ `ps -ef | egrep "statd|lockd" | egrep -v "grep|emi|statdaemon|dsvclockd|kblockd" | wc -l` -gt 0 ] ; then
        result=$result`ps -ef | egrep "statd|lockd" | egrep -v "grep|emi|statdaemon|dsvclockd"`
        check="N"
    else
        result=$result"☞ NFS Client(statd,lockd) Disable"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_25() {
    id="U-25"
    check="Y"
    description="NFS 접근통제"
    start_time=$(test_start $id)
    rsult="■ 기준1: NFS 서버 데몬이 동작하지 않으면 양호\n
           ■ 기준2: NFS 서버 데몬이 동작하는 경우 /etc/exports 파일에 everyone 공유 설정이 없으면 양호\n
            (취약 예문) /tmp/test/share *(rw)"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    result=$result"NFS Server Daemon(nfsd)확인\n"
    result=$result"-----------------------\n"
    if [ `ps -ef | grep nfsd | egrep -v "statdaemon|automountd|emi" | grep -v grep | wc -l` -gt 0 ] ; then
        result=$result`ps -ef | grep nfsd | egrep -v "statdaemon|automountd|emi" | grep -v grep`"\n"
        
        # NFS Server Daemon Running, 접근 통제 여부 확인
        result=$result"\n/etc/exports 파일 설정\n"
        result=$result"-----------------------\n"
        if [ -f /etc/exports ]; then
            if [ `cat /etc/exports | egrep -v "^\s*[#$]" | grep -v "no_root_squash" | wc -l` -gt 0 ]; then
                result=$result`cat /etc/exports`
                check="N"
            else
                result=$result"설정 내용이 없습니다."
            fi
        else
            result=$result"/etc/exports 파일이 없습니다."
        fi
    else
        result=$result"☞ NFS Service Disable\n"
    fi
    
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_26() {
    id="U-26"
    check="Y"
    description="automountd 제거"
    start_time=$(test_start $id)
    result="■ 기준: automountd 서비스가 동작하지 않을 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ `ps -ef | egrep "automount|autofs" | grep -v grep | egrep -v "statdaemon|emi" | wc -l` -gt 0 ] ; then
        result=$result`ps -ef | egrep "automount|autofs" | grep -v grep | egrep -v "statdaemon|emi"`
        check="N"
    else
        result=$result"☞ Automountd Daemon Disable"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_27() {
    id="U-27"
    check="Y"
    description="RPC 서비스 확인"
    start_time=$(test_start $id)
    result="■ 기준: 불필요한 RPC 서비스가 비활성화 되어 있는 경우 양호
            (rpc.cmsd, rpc.ttdbserverd, sadmind, rusersd, walld, sprayd, rstatd, rpc.nisd, rexd, rpc.pcnfsd, rpc.statd, rpc.ypupdated, rpc.rquotad, kcms_server, cachefsd)"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    SERVICE_INETD="rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd"

    if [ -d /etc/xinetd.d ]; then
        if [ `ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD | wc -l` -eq 0 ]; then
            result=$result"불필요한 RPC 서비스가 존재하지 않습니다."
        else
            result=$result`ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD`
            check="N"
        fi
    else
        result=$result"/etc/xinetd.d 디렉토리가 존재하지 않습니다."
    fi

    if command -v rpcinfo >/dev/null; then
        local rpc_services=$(rpcinfo -p | grep -v "program vers proto" | awk '{print $2}')
        if [[ -n "$rpc_services" ]]; then
            result+="[취약] 불필요한 RPC 서비스가 활성화되어 있음\n"
            check="N"
        else
            result+="[양호] 불필요한 RPC 서비스가 비활성화되어 있음\n"
        fi
    else
        result+="[양호] rpcinfo 명령어를 찾을 수 없음\n"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_28() {
    id="U-28"
    check="Y"
    description="NIS, NIS+ 점검"
    start_time=$(test_start $id)
    result="■ 기준: NIS 서비스가 비활성화 되어 있거나, 필요 시 NIS+를 사용하는 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"

    if [ `ps -ef | egrep $SERVICE | grep -v grep | wc -l` -eq 0 ]; then
        result=$result"☞ NIS, NIS+ Service Disable"
    else
        result=$result`ps -ef | egrep $SERVICE | grep -v grep`
        check="N"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_29() {
    id="U-29"
    check="Y"
    description="tftp, talk 서비스 비활성화"
    start_time=$(test_start $id)
    result="■ 기준: tftp, talk, ntalk 서비스가 구동 중이지 않을 경우에 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    result=$result"tftp\n"
    result=$result"-----------------------\n"
    if [ `(netstat -lap 2>/dev/null || ss -lap 2>/dev/null) | grep :tftp | wc -l` -gt 0 ]; then
        result=$result`(netstat -lap 2>/dev/null || ss -lap 2>/dev/null) | grep :tftp`
        check="N"
    else
        result=$result"tftp Service Disable\n"
    fi
    result=$result"\ntalk\n"
    result=$result"-----------------------\n"
    if [ `(netstat -lap 2>/dev/null || ss -lap 2>/dev/null) | grep :talk | wc -l` -gt 0 ]; then
        result=$result`(netstat -lap 2>/dev/null || ss -lap 2>/dev/null) | grep :talk`
        check="N"
    else
        result=$result"talk Service Disable\n"
    fi

    result=$result"\nntalk\n"
    result=$result"-----------------------\n"
    if [ `(netstat -lap 2>/dev/null || ss -lap 2>/dev/null) | grep :ntalk | wc -l` -gt 0 ]; then
        result=$result`(netstat -lap 2>/dev/null || ss -lap 2>/dev/null) | grep :ntalk`
        check="N"
    else
        result=$result"ntalk Service Disable\n"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_30() {
    id="U-30"
    check="Y"
    description="Sendmail 버전 점검"
    start_time=$(test_start $id)
    result="■ 기준: SMTP 서비스를 사용하지 않거나 주기적으로 패치를 관리하고 있을 경우(8.13.8 이상 양호)
             SMTP 서비스를 사용하며 주기적으로 패치를 관리하고 있지 않을 경우(8.13.8 미만 취약)"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ `ps -ef | grep -i sendmail | grep -v grep | wc -l` -gt 0 ]; then
        if [ -f /etc/mail/sendmail.cf ]; then
            result=$result"Version: "`cat /etc/mail/sendmail.cf | grep -i Dz | awk -F/ '{print $1}' | awk -FDZ '{print $2}'`

            if [ 1 -eq `cat /etc/mail/sendmail.cf | grep -i Dz | awk -F/ '{print $1}' | awk -FDZ '{print $2}' | sed -e 's/\.[0-9]*$//' | awk '{if ($1 < 8.13) print 1; else print 0}'` ]; then
                check="N"
            fi
        else
            result=$result"/etc/mail/sendmail.cf이 없습니다."
        fi

    elif [ `ps -ef | grep -i postfix | grep -v grep | wc -l` -gt 0 ]; then
        if [ -f /etc/postfix/main.cf ]; then
            result=$result"Version: "`postconf mail_version | awk -F= '{print $2}' | sed -e 's/\s*//g'`

            if [ 1 -eq `postconf mail_version | awk -F= '{print $2}' | sed -e 's/\s*//g' | sed -e 's/\.[0-9]*$//' | awk '{if ($1 < 3.3) print 1; else print 0}'` ]; then
                check="N"
            fi
        else
            result=$result"/etc/postfix/main.cf이 없습니다."
        fi
    else
        result=$result"SMTP Serevice Disable"
    fi    
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_31() {
    id="U-31"
    check="Y"
    description="스팸 메일 릴레이 제한"
    start_time=$(test_start $id)
    result="■ 기준: SMTP 서비스를 사용하지 않거나 릴레이 제한이 설정되어 있을 경우 양호
            ■ : (R$*         $#error $@ 5.7.1 $: 550 Relaying denied 해당 설정에 주석이 제거되어 있으면 양호)"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    # sendmail
    if [[ `(netstat -lap  2>/dev/null || ss -lap  2>/dev/null ) | grep :ftp | grep -v "grep" | wc -l` -gt 0 ]]; then
        if [ `ps -ef | grep -i sendmail | grep -v grep | wc -l` -gt 0 ]; then
            if [ -f /etc/mail/sendmail.cf ]; then
                result=$result"/etc/mail/sendmail.cf\n"
                result=$result"-----------------------\n"
                result=$result`cat /etc/mail/sendmail.cf | grep "R$\*" | grep "Relaying denied"`
                
                if [ `cat /etc/mail/sendmail.cf | egrep -v "^\s*[#$]" | grep "R$\*" | grep "Relaying denied" | wc -l` -eq 0 ]; then
                    check="N"
                fi
            else
                result=$result"/etc/mail/sendmail.cf이 없습니다."
            fi
        fi
        
        # postfix
        if [ `ps -ef | grep -i postfix | grep -v grep | wc -l` -gt 0 ]; then
            if [ -f /etc/postfix/main.cf ]; then
                result=$result"/etc/postfix/main.cf\n"
                result=$result"-----------------------\n"
                result=$result`cat /etc/postfix/main.cf | egrep "restrictions"`
                if [ `cat /etc/postfix/main.cf | egrep -v "^\s*[#$]" | egrep "restrictions" | grep "mynetworks" | wc -l` -eq 0 ]; then
                    check="N"
                fi
            else
                result=$result"/etc/postfix/main.cf이 없습니다."
            fi
        fi
    else
        result=$result"SMTP Serevice Disable"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_32() {
    id="U-32"
    check="Y"
    description="일반사용자의 Sendmail 실행 방지"
    start_time=$(test_start $id)
    result="■ 기준: SMTP 서비스를 사용하지 않거나 릴레이 제한이 설정되어 있을 경우 양호
            ■ : (PrivacyOptions 내에 restrictqrun 존재)"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    result=$result"/etc/mail/sendmail.cf 파일의 옵션 확인\n"
    if [[ `which netstat` && `netstat -lap | grep :smtp | wc -l` -gt 0 ]]  || [[ `which ss` && `ss -lap | grep :smtp | wc -l` -gt 0 ]]; then
        if [ -f /etc/mail/sendmail.cf ]; then
            result=$result`egrep -v '^\s*(#|$)' /etc/mail/sendmail.cf | grep "PrivacyOptions" | grep "restrictqrun"`
            if [ `egrep -v '^\s*(#|$)' /etc/mail/sendmail.cf | grep "PrivacyOptions" | grep "restrictqrun" | wc -l` -eq 0 ]; then
                check="N"
            fi  
        else
            result=$result"/etc/mail/sendmail.cf 파일이 없습니다."
        fi
    else
        result=$result"SMTP Serevice Disable"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 


test_U_33() {
    id="U-33"
    check="Y"
    description="DNS 보안 버전 패치"
    start_time=$(test_start $id)
    result="■ 기준: DNS 서비스를 사용하지 않거나, 양호한 버전을 사용하고 있을 경우에 양호
            ■ : (양호한 버전: 9.18.0, 9.16.26, 9.11.36)"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ `((systemctl --type=service --state=running 2>/dev/null) || (service --status-all 2>/dev/null | egrep "running|enabled" )) | egrep "name" | wc -l` -gt 0 ];then
        result=$result"Version: "`named -v | awk '{print $2}' | awk -F- '{print $1}'`
        if [ `named -v | awk '{print $2}' | awk -F- '{print $1}' | sed -e 's/\.[0-9]*$//' | awk '{if ($1 < 9) print 1; else print 0}'` -eq 1 ]; then
            check="N"
        fi
    else
        result=$result"DNS Service Disable"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_34() {
    id="U-34"
    check="Y"
    description="DNS ZoneTransfer 설정"
    start_time=$(test_start $id)
    result="■ 기준: DNS 서비스를 사용하지 않거나 Zone Transfer 가 제한되어 있을 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    #① DNS 프로세스 확인 
    if [ `((systemctl --type=service --state=running 2>/dev/null) || (service --status-all 2>/dev/null | egrep "running|enabled" )) | egrep "name" | wc -l` -gt 0 ]; then
        if [ -f "/etc/named.conf" ]; then
            CONF="/etc/named.conf"
        elif [ -f "/etc/bind/named.conf" ]; then
            CONF="/etc/bind/named.conf"
        elif [ -f "/etc/named/named.conf" ]; then
            CONF="/etc/named/named.conf"
        else
            result=$result"named.conf 파일 없음."
        fi

        if [ -f $CONF ]; then
            BIND_CONF=`cat $CONF $(cat $CONF | grep include | awk '{print $2}' | sed -e's/[;\"]//g') | egrep -v '^\s*(#|$|\/\/)'`
            
            result=$result"/etc/named.conf 파일의 allow-transfer 확인\n"
            result=$result"------------------------------------\n"
            result=$result`grep -i "allow-transfer" $CONF`"\n\n"

            if [ `grep -i "allow-transfer" $CONF | wc -l` -gt 0 ]; then
                if [ `cat $CONF | grep -i "allow-transfer" | grep "0.0.0.0" | wc -l` -gt 0 ]; then
                    check="N"
                fi
            else
                result=$result"allow-transfer 설정 없음(Default None).\n"
            fi
        fi
    else
        result=$result"DNS Service Disable\n"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_35() {
    id="U-35"
    check="Y"
    description="Apache 디렉터리 리스팅 제거"
    start_time=$(test_start $id)
    result="■ 기준: httpd.conf 파일의 Directory 부분의 Options 지시자에 Indexes가 설정되어 있지 않으면 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ `ps -ef | egrep "apache|httpd" | grep -v "grep" | wc -l` -gt 0 ]; then
        if [ "$OS" == "Ubuntu" ] || [ "$OS" == "Debian" ]; then
            AP_ROOT_DIR=`apache2 -V 2>/dev/null | grep HTTPD_ROOT | awk -F= '{print $2}' | sed 's/"//g'`
            AP_CONFIG=`apache2 -V 2>/dev/null | grep SERVER_CONFIG_FILE | awk -F= '{print $2}' | sed -e 's/"//g'`
            
        else
            AP_ROOT_DIR=`httpd -V 2>/dev/null | grep HTTPD_ROOT | awk -F= '{print $2}' | sed -e 's/"//g'`
            AP_CONFIG=`httpd -V 2>/dev/null | grep SERVER_CONFIG_FILE | awk -F= '{print $2}' | sed -e 's/"//g'`
        fi
        CONFIG=$AP_ROOT_DIR/$AP_CONFIG

        if [ -f $CONFIG ]; then
            result=$result`cat $CONFIG | egrep -v '^\s*(#|$)' | sed -n -e '/<Directory/, /<\/Directory>$/p'`
            if [ `cat $CONFIG | egrep -v '^\s*(#|$)' | egrep -v '\-Indexes' | grep "Option.*Indexes" | wc -l` -gt 0 ]; then
                check="N"
            fi
        else
            check="-"
            result=$result"설정파일 확인 불가(수동점검)"
        fi
    else
        result=$result"Apache Service Disable"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_36() {
    id="U-36"
    check="Y"
    description="Apache 웹 프로세스 권한 제한"
    start_time=$(test_start $id)
    result="■ 기준: 웹 프로세스 권한을 제한 했을 경우 양호(User root, Group root 가 아닌 경우)"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ `ps -ef | egrep "apache|httpd" | grep -v "grep" | wc -l` -gt 0 ]; then
        if [ "$OS" == "Ubuntu" ] || [ "$OS" == "Debian" ]; then
            AP_ROOT_DIR=`apache2 -V 2>/dev/null | grep HTTPD_ROOT | awk -F= '{print $2}' | sed 's/"//g'`
            AP_CONFIG=`apache2 -V 2>/dev/null | grep SERVER_CONFIG_FILE | awk -F= '{print $2}' | sed -e 's/"//g'`
            
        else
            AP_ROOT_DIR=`httpd -V 2>/dev/null | grep HTTPD_ROOT | awk -F= '{print $2}' | sed -e 's/"//g'`
            AP_CONFIG=`httpd -V 2>/dev/null | grep SERVER_CONFIG_FILE | awk -F= '{print $2}' | sed -e 's/"//g'`
        fi
        CONFIG=$AP_ROOT_DIR/$AP_CONFIG

        if [ -f $CONFIG ]; then
            USER=`cat $CONFIG | egrep -v '^\s*(#|$)' | grep -i User | egrep -v '^LoadModule|LogFormat|IfModule|UserDir' | awk '{print $2}'`
            GROUP=`cat $CONFIG | egrep -v '^\s*(#|$)' | grep -i Group | egrep -v '^LoadModule|LogFormat|IfModule|UserDir' | awk '{print $2}'`
            if [[ "$USER" == *"APACHE_RUN_USER"* ]]; then
                USER=`cat $AP_ROOT_DIR/envvars| grep "APACHE_RUN_USER" | awk -F= '{print $2}'`
            fi

            if [[ "$GROUP" == *"APACHE_RUN_GROUP"* ]]; then
                GROUP=`cat $AP_ROOT_DIR/envvars| grep "APACHE_RUN_GROUP" | awk -F= '{print $2}'`
            fi
            
            result=$result"USER=$USER\nGroup=$GROUP"
            if [ "$USER" == "root" ] || [ "$GROUP" == "root" ]; then
                check="N"
            fi
        else
            check="-"
            result=$result"$CONFIG 파일 없음"
        fi
    else
        result=$result"Apache Service Disable"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_37() {
    id="U-37"
    check="Y"
    description="Apache 상위 디렉터리 접근 금지"
    start_time=$(test_start $id)
    result="■ 기준: httpd.conf 파일의 Directory 부분의 AllowOverride None 설정이 아니면 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ `ps -ef | egrep "apache|httpd" | grep -v "grep" | wc -l` -gt 0 ]; then
        if [ "$OS" == "Ubuntu" ] || [ "$OS" == "Debian" ]; then
            AP_ROOT_DIR=`apache2 -V 2>/dev/null | grep HTTPD_ROOT | awk -F= '{print $2}' | sed 's/"//g'`
            AP_CONFIG=`apache2 -V 2>/dev/null | grep SERVER_CONFIG_FILE | awk -F= '{print $2}' | sed -e 's/"//g'`
            
        else
            AP_ROOT_DIR=`httpd -V 2>/dev/null | grep HTTPD_ROOT | awk -F= '{print $2}' | sed -e 's/"//g'`
            AP_CONFIG=`httpd -V 2>/dev/null | grep SERVER_CONFIG_FILE | awk -F= '{print $2}' | sed -e 's/"//g'`
        fi
        CONFIG=$AP_ROOT_DIR/$AP_CONFIG

        if [ -f $CONFIG ]; then
            result=$result`cat $CONFIG | egrep -v '^\s*(#|$)' | sed -n -e '/<Directory/, /<\/Directory>$/p'`
            if [ `cat $CONFIG | egrep -v '^\s*(#|$)' | grep "AllowOverride\s*None" | wc -l` -gt 0 ]; then
                check="N"
            fi
        else
            check="-"
            result=$result"설정파일 확인 불가(수동점검)"
        fi
    else
        result=$result"Apache Service Disable"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_38() {
    id="U-38"
    check="Y"
    description="Apache 불필요한 파일 제거"
    start_time=$(test_start $id)
    result="■ 기준: /htdocs/manual 또는 /apache/manual 디렉터리와 /cgi-bin/test-cgi, /cgi-bin/printenv 파일이 제거되어 있는 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ `ps -ef | egrep "apache|httpd" | grep -v "grep" | wc -l` -gt 0 ]; then
        if [ "$OS" == "Ubuntu" ] || [ "$OS" == "Debian" ]; then
            AP_ROOT_DIR=`apache2 -V 2>/dev/null | grep HTTPD_ROOT | awk -F= '{print $2}' | sed 's/"//g'`
            AP_CONFIG=`apache2 -V 2>/dev/null | grep SERVER_CONFIG_FILE | awk -F= '{print $2}' | sed -e 's/"//g'`
            
        else
            AP_ROOT_DIR=`httpd -V 2>/dev/null | grep HTTPD_ROOT | awk -F= '{print $2}' | sed -e 's/"//g'`
            AP_CONFIG=`httpd -V 2>/dev/null | grep SERVER_CONFIG_FILE | awk -F= '{print $2}' | sed -e 's/"//g'`
        fi
        
        result=$result"\n$AP_ROOT_DIR/cgi-bin 파일\n"
        result=$result"--------------------------\n"
        if [ -d $AP_ROOT_DIR/cgi-bin ]; then
            result=$result`ls -ld $AP_ROOT_DIR/cgi-bin/test-cgi`
            result=$result`ls -ld $AP_ROOT_DIR/cgi-bin/printenv`
            check="N"
        else
            result=$result"$AP_ROOT_DIR/cgi-bin 디렉터리가 제거되어 있습니다.(양호)\n"
        fi
        
        result=$result"\n$AP_ROOT_DIR/htdocs/manual 파일\n"
        result=$result"--------------------------\n"
        if [ -d $AP_ROOT_DIR/htdocs/manual ]; then
            result=$result`ls -ld $AP_ROOT_DIR/htdocs/manual\n`
            check="N"

        else
            result=$result"☞ $AP_ROOT_DIR/htdocs/manual 디렉터리가 제거되어 있습니다.(양호)\n"
        fi

        result=$result"\n$AP_ROOT_DIR/manual 파일\n"
        result=$result"--------------------------\n"
        if [ -d $AP_ROOT_DIR/manual ]; then
            result=$result`ls -ld $AP_ROOT_DIR/manual\n`
            check="N"
        else
            result=$result"☞ $AP_ROOT_DIR/manual 디렉터리가 제거되어 있습니다.(양호)\n"
        fi
    else
        result=$result"Apache Service Disable"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_39() {
    id="U-39"
    check="Y"
    description="Apache 링크 사용금지"
    start_time=$(test_start $id)
    result="■ 기준: Options 지시자에서 심블릭 링크를 가능하게 하는 옵션인 FollowSymLinks가 제거된 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ `ps -ef | egrep "apache|httpd" | grep -v "grep" | wc -l` -gt 0 ]; then
        if [ "$OS" == "Ubuntu" ] || [ "$OS" == "Debian" ]; then
            AP_ROOT_DIR=`apache2 -V 2>/dev/null | grep HTTPD_ROOT | awk -F= '{print $2}' | sed 's/"//g'`
            AP_CONFIG=`apache2 -V 2>/dev/null | grep SERVER_CONFIG_FILE | awk -F= '{print $2}' | sed -e 's/"//g'`
            
        else
            AP_ROOT_DIR=`httpd -V 2>/dev/null | grep HTTPD_ROOT | awk -F= '{print $2}' | sed -e 's/"//g'`
            AP_CONFIG=`httpd -V 2>/dev/null | grep SERVER_CONFIG_FILE | awk -F= '{print $2}' | sed -e 's/"//g'`
        fi
        CONFIG=$AP_ROOT_DIR/$AP_CONFIG

        if [ -f $CONFIG ]; then
            result=$result`cat $CONFIG | egrep -v '^\s*(#|$)' | sed -n -e '/<Directory/, /<\/Directory>$/p'`
            if [ `cat $CONFIG | egrep -v '^\s*(#|$)' | grep "FollowSymLinks" | wc -l` -gt 0 ]; then
                check="N"
            fi
        else
            check="-"
            result=$result"설정파일 확인 불가(수동점검)"
        fi
    else
        result=$result"Apache Service Disable"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_40() {
    id="U-40"
    check="Y"
    description="Apache 파일 업로드 및 다운로드 제한"
    start_time=$(test_start $id)
    result="■ 기준: 시스템에 따라 파일 업로드 및 다운로드에 대한 용량이 제한되어 있는 경우 양호
            ■ <Directory 경로>의 LimitRequestBody 지시자에 제한용량이 설정되어 있는 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ `ps -ef | egrep "apache|httpd" | grep -v "grep" | wc -l` -gt 0 ]; then
        if [ "$OS" == "Ubuntu" ] || [ "$OS" == "Debian" ]; then
            AP_ROOT_DIR=`apache2 -V 2>/dev/null | grep HTTPD_ROOT | awk -F= '{print $2}' | sed 's/"//g'`
            AP_CONFIG=`apache2 -V 2>/dev/null | grep SERVER_CONFIG_FILE | awk -F= '{print $2}' | sed -e 's/"//g'`
            
        else
            AP_ROOT_DIR=`httpd -V 2>/dev/null | grep HTTPD_ROOT | awk -F= '{print $2}' | sed -e 's/"//g'`
            AP_CONFIG=`httpd -V 2>/dev/null | grep SERVER_CONFIG_FILE | awk -F= '{print $2}' | sed -e 's/"//g'`
        fi
        CONFIG=$AP_ROOT_DIR/$AP_CONFIG

        if [ -f $CONFIG ]; then
            CONT_DIR=`cat $CONFIG | egrep -v '^\s*(#|$)' | egrep '<Directory ' | wc -l`
            result=$result`cat $CONFIG | egrep -v '^\s*(#|$)' | sed -n -e '/<Directory/, /<\/Directory>$/p'`
            if [ `cat $CONFIG | egrep -v '^\s*(#|$)' | grep "LimitRequestBody" | wc -l` -lt $CONT_DIR ]; then
                check="N"
            fi
        else
            check="-"
            result=$result"설정파일 확인 불가(수동점검)"
        fi
    else
        result=$result"Apache Service Disable"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_41() {
    id="U-41"
    check="Y"
    description="Apache 웹 서비스 영역의 분리"
    start_time=$(test_start $id)
    result="■ 기준: DocumentRoot를 기본 디렉터리가 아닌 별도의 디렉토리로 지정한 경우 양호
            Default Path: ~/apache/htdocs ~/apache2/htdocsf /var/www/html"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ `ps -ef | egrep "apache|httpd" | grep -v "grep" | wc -l` -gt 0 ]; then
        if [ "$OS" == "Ubuntu" ] || [ "$OS" == "Debian" ]; then
            AP_ROOT_DIR=`apache2 -V 2>/dev/null | grep HTTPD_ROOT | awk -F= '{print $2}' | sed 's/"//g'`
            AP_CONFIG=`apache2 -V 2>/dev/null | grep SERVER_CONFIG_FILE | awk -F= '{print $2}' | sed -e 's/"//g'`
            
        else
            AP_ROOT_DIR=`httpd -V 2>/dev/null | grep HTTPD_ROOT | awk -F= '{print $2}' | sed -e 's/"//g'`
            AP_CONFIG=`httpd -V 2>/dev/null | grep SERVER_CONFIG_FILE | awk -F= '{print $2}' | sed -e 's/"//g'`
        fi
        CONFIG=$AP_ROOT_DIR/$AP_CONFIG

        if [ -f $CONFIG ]; then
            result=$result`grep -r 'DocumentRoot' $AP_ROOT_DIR | grep -v "#"`
            for line in `grep -r 'DocumentRoot' $AP_ROOT_DIR | grep -v '#' | sed 's/DocumentRoot/ /g' | sed 's/\"//g' | awk '{print $1 $2}'`
            do
                DocumentRoot=`echo $line | awk -F: '{print $2}'`
                if [ $DocumentRoot == "*/apache/htdocs" ]; then
                    check="N"
                elif [ $DocumentRoot == "*/apache2/htdocs" ]; then
                    check="N"
                elif [ $DocumentRoot == "/var/www/html" ]; then
                    check="N"
                fi
            done
        else
            check="-"
            result=$result"설정파일 확인 불가(수동점검)"
        fi
    else
        result=$result"Apache Service Disable"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_42() {
    id="U-42"
    check="-"
    description="최신 보안패치 및 벤더 권고사항 적용"
    start_time=$(test_start $id)
    result="■ 기준: 패치 적용 정책을 수립하여 주기적으로 패치를 관리하고 있을 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    result=$result`lsb_release -a 2>/dev/null && uname -a`
    result=$result"\n업데이트 가능한 보안업데이트 목록\n"
    
    if [ "$OS" == "Ubuntu" ] || [ "$OS" == "Debian" ]; then
        apt update 1>/dev/null 2>/dev/null
        result=$result`apt-get upgrade -s | grep ^Inst | grep -i security`
    else
        result=$result`yum list-security --security`
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_43() {
    id="U-43"
    check="-"
    description="로그의 정기적 검토 및 보고"
    start_time=$(test_start $id)
    result="■ 기준: 로그를 정기적으로 검토하고 있을 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    result=$result"인터뷰"
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_44() {
    id="U-44"
    check="Y"
    description="root 이외의 UID가 '0' 금지"
    start_time=$(test_start $id)
    result="■ 기준: root 계정만이 UID가 0이면 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ -f /etc/passwd ]; then
        result=$result`awk -F: '$3==0 { print $1 " -> UID=" $3 }' /etc/passwd`
        if [ `awk -F: '$3==0 { print $1 " -> UID=" $3 }' /etc/passwd | grep -v "root" | wc -l` -gt 0 ]; then
            check="N"
        fi
    else
        check="-"
        echo "☞ /etc/passwd 파일이 없습니다.\n"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 


test_U_45() {
    id="U-45"
    check="-"
    description="root 계정 su 제한"
    start_time=$(test_start $id)
    result="■ 기준1: /etc/pam.d/su 파일 설정이 아래와 같을 경우 양호
            ■ 기준2: 아래 설정이 없거나, 주석 처리가 되어 있을 경우 su 명령 파일의 권한이 4750 이면 양호
            ■        : (auth  required  /lib/security/pam_wheel.so debug group=wheel) 또는
            ■        : (auth  required  /lib/security/\$ISA/pam_wheel.so use_uid)"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    result=$result"Login 가능 user(/etc/passwd)\n"
    result=$result`cat /etc/passwd | egrep '\/.*sh$'`"\n\n"

    if [ "$OS" == "Ubuntu" ] || [ "$OS" == "Debian" ]; then
        result=$result`cat /etc/sudoers $(find /etc/sudoers.d -exec ls {} \; | grep /etc) | egrep -v "^\s*(#|$)"`
    else
        result=$result"wheel group\n"
        result=$result`cat /etc/group`
        result=$result"\n\n"
        result=$result"/etc/pam.d/su\n"
        result=$result`cat /etc/pam.d/su`
        result=$result"\n\n"
        result=$result"/bin/su\n"
        result=$result`ls -l /bin/su`
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_46() {
    id="U-46"
    check="Y"
    description="패스워드 최소 길이 설정"
    start_time=$(test_start $id)
    result="■ 기준: 패스워드 최소 길이가 8자 이상으로 설정되어 있으면 양호
            ■ : (PASS_MIN_LEN 8 이상이면 양호)"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ -f /etc/login.defs ]; then
        #    grep -v '^ *#' /etc/login.defs | grep -i "PASS_MIN_LEN"
        result=$result`cat /etc/login.defs | grep "PASS_MIN_LEN"`"\n"
        if [ `cat /etc/login.defs | egrep -v "^\s*#" | grep "PASS_MIN_LEN" | wc -l` -gt 0 ]; then
            if [ `cat /etc/login.defs | egrep -v "^\s*#" | grep "PASS_MIN_LEN" | awk '{print $2}'` -lt 8 ]; then
                check="N"
            fi
        else
            check="N"
        fi
    else
        result=$result"/etc/login.defs 파일이 없습니다.\n\n"
    fi

    if [ -f /etc/pam.d/sshd ]; then
        # Google OTP use
        result=$result"\nOTP 사용 여부\n"
        result=$result"-----------------------\n"
        if [ `cat /etc/pam.d/sshd | egrep -v "^\s*(#|$)" | grep "pam_google_authenticator.so" | wc -l` -gt 0 ]; then
            if [ `cat /etc/ssh/sshd_config | egrep -v "^\s*(#|$)" | grep "^\s*PasswordAuthentication\s*no" | wc -l` -gt 0 ]; then
                check="Y"
                result=$result"OTP 사용 중\n"
            else
                result=$result"OTP 미사용"
            fi
        else
            result=$result"OTP 미사용"
        fi    
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_47() {  
    id="U-47"
    check="Y"
    description="패스워드 최대 사용 기간 설정"
    start_time=$(test_start $id)
    result="■ 기준: 패스워드 최대 사용기간이 90일 이하로 설정되어 있으면 양호
            ■ : (PASS_MAX_DAYS 90 이하이면 양호)"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ -f /etc/login.defs ]; then
        result=$result`cat /etc/login.defs | grep -i "PASS_MAX_DAYS" | grep -v "number of"`
        if [ `cat /etc/login.defs | egrep -v "^\s*(#|$)" | grep -i "PASS_MAX_DAYS" | awk '{print $2}'` -gt 90 ]; then
            check="N"            
        fi
    fi

    if [ -f /etc/pam.d/sshd ]; then
        # Google OTP use
        result=$result"\n\nOTP 사용 여부\n"
        result=$result"-----------------------\n"
        if [ `cat /etc/pam.d/sshd | egrep -v "^\s*(#|$)" | grep "pam_google_authenticator.so" | wc -l` -gt 0 ]; then
            if [ `cat /etc/ssh/sshd_config | egrep -v "^\s*(#|$)" | grep "^\s*PasswordAuthentication\s*no" | wc -l` -gt 0 ]; then
                check="Y"
                result=$result"OTP 사용 중\n"
            else
                result=$result"OTP 미사용"
            fi
        else
            result=$result"OTP 미사용"
        fi    
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_48() {
    id="U-48"
    check="Y"
    description="패스워드 최소 사용기간 설정"
    start_time=$(test_start $id)
    result="■ 기준: 패스워드 최소 사용기간이 1일로 설정되어 있으면 양호
            ■ : (PASS_MIN_DAYS 1 이상이면 양호) "
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ -f /etc/login.defs ]; then
        result=$result`cat /etc/login.defs | grep -i "PASS_MIN_DAYS" | grep -v "number of"`
        if [ `cat /etc/login.defs | egrep -v "^\s*(#|$)" | grep -i "PASS_MIN_DAYS" | awk '{print $2}'` -lt 1 ]; then
            check="N"
        fi
    fi

    if [ -f /etc/pam.d/sshd ]; then
        # Google OTP use
        result=$result"\n\nOTP 사용 여부\n"
        result=$result"-----------------------\n"
        if [ `cat /etc/pam.d/sshd | egrep -v "^\s*(#|$)" | grep "pam_google_authenticator.so" | wc -l` -gt 0 ]; then
            if [ `cat /etc/ssh/sshd_config | egrep -v "^\s*(#|$)" | grep "^\s*PasswordAuthentication\s*no" | wc -l` -gt 0 ]; then
                check="Y"
                result=$result"OTP 사용 중\n"
            else
                result=$result"OTP 미사용"
            fi
        else
            result=$result"OTP 미사용"
        fi    
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_49() {
    id="U-49"
    check="Y"
    description="불필요한 계정 제거"
    start_time=$(test_start $id)
    result="■ 기준: /etc/passwd 파일에 lp, uucp, nuucp 계정이 모두 제거되어 있으면 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##

    # non need user check
    CheckUser=`cat /etc/passwd | egrep -v "^\s*(#|$)" | egrep "^adm|^lp|^uucp|^nuucp|^sync|^shutdown|^halt|^news|^operator|^games|^gopher|^nfsnobody|^squid"`
    result=$result"불필요 계정 현황\n"
    result=$result"-----------------------\n"

    if [ `echo $CheckUser | egrep "sh$" | wc -l` -gt 0 ]; then
        check="N"
        result=$result`echo $CheckUser | egrep "sh$"`
    else
        result=$result"불필요 계정 없음\n"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_50() {
    id="U-50"
    check="Y"
    description="관리자 그룹에 최소한의 계정 포함"
    start_time=$(test_start $id)
    result="■ 기준: 관리자 계정이 포함된 그룹에 불필요한 계정이 존재하지 않는 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    result=$result"관리자 계정\n"
    result=$result`cat /etc/passwd | egrep -v "^\s*(#|$)" | awk -F: '{ if( $3 == '0' ) print "UID=0 USER: "$1 }'`"\n\n"
    if [ `cat /etc/passwd | awk -F: '{ if($3=='0') print $1 }' | grep -v root | wc -l` -gt 0 ]; then
        check="N"
    fi

    result=$result"관리자 계정이 속한 그룹\n"
    tmp_check=True
    for group in `awk -F: '$3 == 0 {print $1}' /etc/passwd`
    do
        if [ `cat /etc/group | grep $group | wc -l` -gt 0 ]; then
            result=$result`cat /etc/group | grep $group`
            tmp_check=False
        fi 
    done

    # 관리자 계정 포함 그룹 확인 필요.
    if [ $check == Fail ] && [ $tmp_check == False ]; then
        check="-"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 


test_U_51() {
    id="U-51"
    check="Y"
    description="계정이 존재하지 않는 GID 금지"
    start_time=$(test_start $id)
    result="■ 기준: 구성원이 존재하지 않는 빈 그룹이 존재하지 않을 경우 양호
            GID 1000이상 구성원 없는 그룹 존재 시 취약"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    # non user user Group
    result=$result"계정이 존재하지 않는 Group\n"
    result=$result"-----------------------\n"
    for group in `awk -F: '{ if($4==null && $3 >= 1000) print $1}' /etc/group | grep -v nogroup` 
    do
        if [ `grep $group /etc/passwd | wc -l` -eq 0 ]; then
            result=$result`grep $group /etc/group`"\n"
            check="N"
        fi
    done
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_52() {
    id="U-52"
    check="Y"
    description="동일한 UID 금지"
    start_time=$(test_start $id)
    result="■ 기준: 동일한 UID로 설정된 계정이 존재하지 않을 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    result=$result"동일한 UID 계정 현황\n"
    result=$result"-----------------------\n"
    for uid in `cat /etc/passwd | awk -F: '{print $3}'`
    do
        if [ `cat /etc/passwd | awk -F: '{ if($3=="${uid}") print $0 }' | wc -l` -gt 1 ]; then
            check="N"
            result=$result`cat /etc/passwd | awk -F: '{ if($3=="${uid}") print $0 }'`"\n"
        fi
    done
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_53() {
    id="U-53"
    check="Y"
    description="사용자 Shell 점검"
    start_time=$(test_start $id)
    result="■ 기준: 로그인이 필요하지 않은 계정의 /bin/false(nologin) 쉘이 부여되어 있을 경우
             로그인이 필요하지 않은 계정의 /bin/false(nologin) 쉘이 부여되어 있지 않을 경우"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##

    # non need user check
    result=$result"시스템 계정 Shell 할당 현황.\n"
    result=$result"-----------------------\n"
    if [ `cat /etc/passwd | egrep "^adm|^lp|^uucp|^nuucp|^sync|^shutdown|^halt|^news|^operator|^games|^gopher|^nfsnobody|^squid" | egrep ".*sh$" | wc -l` -gt 0 ]; then
        result=$result`cat /etc/passwd | egrep "^adm|^lp|^uucp|^nuucp|^sync|^shutdown|^halt|^news|^operator|^games|^gopher|^nfsnobody|^squid" | egrep ".*sh$"`
        check="N"
    else
        result=$result"불필요 계정 없음\n"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_54() {
    id="U-54"
    check="Y"
    description="Session Timeout 설정"
    start_time=$(test_start $id)
    result="■ 기준: /etc/profile 에서 TMOUT=300 또는 /etc/csh.login 에서 autologout=5 로 설정되어 있으면 양호
            ■ : (1) sh, ksh, bash 쉘의 경우 /etc/profile 파일 설정을 적용받음
            ■ : (2) csh, tcsh 쉘의 경우 /etc/csh.cshrc 또는 /etc/csh.login 파일 설정을 적용받음"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    result=$result"ENV\n"
    result=$result"------------------------\n"
    if [ `set | egrep -i ^TMOUT | wc -l` -gt 0 ]; then
        if [ `set | egrep -i ^TMOUT | awk -F '{print $2}'` -gt 300 ]; then
            check="N"
        else
            result=$result`set | egrep -i ^TMOUT`
        fi
    elif [ `set | egrep -i ^autologout | wc -l` -gt 0 ]; then
        if [ `set  | egrep -t ^autologout | awk -F= '{print $2}'` -gt 5 ]; then
            check="N"
        else
            result=$result`set | grep -i ^autologout`
        fi
    else
        result=$result"TMOUT 이 설정되어 있지 않습니다.\n"
        check="N"
    fi

    result=$result"\n/etc/profile\n"
    result=$result"------------------------\n"
    if [ -f /etc/profile ]; then
        result=$result"/etc/profile\n"
        if [ `cat /etc/profile | grep -v "^\s*#" | grep -i TMOUT | wc -l` -gt 0 ]; then
            result=$result`cat /etc/profile | grep -v "^\s*#" | grep -i TMOUT`
        else
            result=$result"TMOUT 이 설정되어 있지 않습니다.\n"
        fi
    else
        result=$result"/etc/profile 파일이 없습니다.\n"
    fi

    
    result=$result"\n/etc/profile.d/ \n"
    result=$result"------------------------\n"
    if [ -d /etc/profile.d ]; then
        result=$result"/etc/profile.d*\n"
        if [ `grep -i TMOUT /etc/profile.d/* | grep -v "^\s*#" | wc -l` -gt 0 ]; then
            result=$result`cat /etc/profile | grep -v "^\s*#" | grep -i TMOUT`
        else
            result=$result"TMOUT 이 설정되어 있지 않습니다.\n"
        fi
    else
        result=$result"/etc/profile 파일이 없습니다.\n"
    fi
 
    result=$result"\n/etc/csh.login\n"
    result=$result"------------------------\n"
    if [ -f /etc/csh.login ]; then
        result=$result"/etc/csh.login\n"
        if [ `cat /etc/csh.login | grep -i autologout | grep -v "^\s*#" | wc -l` -gt 0 ]; then
            result=$result`cat /etc/csh.login | grep -i autologout | grep -v "^\s*#"`
        else
            result=$result"autologout 이 설정되어 있지 않습니다.\n"
        fi
    else
        result=$result"/etc/csh.login 파일이 없습니다.\n"
    fi

    result=$result"\n/etc/csh.cshrc\n"
    result=$result"------------------------\n"
    if [ -f /etc/csh.cshrc ]; then
        result=$result"/etc/csh.cshrc\n"
        if [ `cat /etc/csh.cshrc | grep -i autologout | grep -v "^\s*#" | wc -l` -gt 0 ]; then
            result=$result`cat /etc/csh.cshrc | grep -i autologout | grep -v "^\s*#"`
        else
            result=$result"autologout 이 설정되어 있지 않습니다.\n"
        fi
    else
        result=$result"/etc/csh.cshrc 파일이 없습니다.\n"
    fi

    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_55() {
    id="U-55"
    check="Y"
    description="hosts.lpd 파일 소유자 및 권한 설정"
    start_time=$(test_start $id)
    result="■ 기준: /etc/host.lpd 파일의 소유자가 root 이고, 권한이 600 이하인 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ -f /etc/host.lpd ]; then
        result=$result`ls -l /etc/host.lpd`
        if [ `stat -c "%a" /etc/host.lpd` -gt 600 ] || [ `stat -c "%U" /etc/host.lpd` != 'root' ]; then
            check="N"
        fi
    else
        result=$result"/etc/host.lpd 파일이 없습니다."
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_56() {
    id="U-56"
    check="Y"
    description="NIS 서비스 비활성화"
    start_time=$(test_start $id)
    result="■ 기준: 불필요한 NIS 서비스가 비활성화 되어있는 경우"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"

    if [ `ps -ef | grep $SERVICE | grep -v grep | wc -l` -eq 0 ]; then
        result=$result"☞ NIS Service Disable"
    else
        result=$result`ps -ef | grep $SERVICE | grep -v grep`
        check="N"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_57() {
    id="U-57"
    check="-"
    description="UMASK 설정 관리"
    start_time=$(test_start $id)
    result="■ 기준: UMASK 값이 022 이면 양호
            ■ : (1) sh, ksh, bash 쉘의 경우 /etc/profile 파일 설정을 적용받음
            ■ : (2) csh, tcsh 쉘의 경우 /etc/csh.cshrc 또는 /etc/csh.login 파일 설정을 적용받음"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    result=$result"UMASK "`umask`
    result=$result"\n/etc/pam.d/common-session\n"
    result=$result"------------------------\n"
    if [ -f /etc/pam.d/common-session ]; then
        if [ `cat /etc/pam.d/common-session | grep -v "^\s*(#|$)" | grep "umask" | wc -l` -gt 0 ]; then
            result=$result`cat /etc/pam.d/common-session | grep "umask="`
        else
            result=$result"Umask 설정 없음.\n"
        fi
    fi

    result=$result"\n\n/etc/profile\n"
    result=$result"------------------------\n"
    if [ -f /etc/profile ]; then
        if [ `cat /etc/profile | grep -v "^\s*(#|$)" | grep "umask" | wc -l` -gt 0 ]; then
            result=$result`cat /etc/profile | grep -B1 umask`
        else
            result=$result"Umask 설정 없음.\n"
        fi
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
}

test_U_58() {
    id="U-58"
    check="Y"
    description="홈 디렉터리 소유자 및 권한 설정"
    start_time=$(test_start $id)
    result="■ 기준: 홈 디렉터리의 소유자가 /etc/passwd 내에 등록된 홈 디렉터리 사용자와 일치하고,"
    result=$result"■     : 홈 디렉터리에 타사용자 쓰기권한이 없으면 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    while read line
    do
        USER=`echo $line | awk -F: '{print $1}'`
        HOMEDIR=`echo $line | awk -F: '{print $6}'`

        if [ `echo $line | awk -F: '{print $3}'` -ge 1000 ]; then
            if [ -d $HOMEDIR ]; then
                result=$result"$USER: "`ls -ld $HOMEDIR`"\n"
                if [ `stat -c "%U" $HOMEDIR` != $USER ] || [ `ls -ld $HOMEDIR | egrep '........w.' | wc -l` -gt 0 ]; then
                    check="N"
                fi
            fi
        fi
    done < /etc/passwd
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_59() {
    id="U-59"
    check="Y"
    description="홈 디렉터리로 지정한 디렉터리의 존재 관리"
    start_time=$(test_start $id)
    result="■ 기준: 홈 디렉터리가 존재하지 않는 계정이 발견되지 않으면 양호
            홈 디렉토리가 존재하지 않는 경우, 일반 사용자가 로그인을 하면 사용자의 현재 디렉터리가 /로 로그인 되므로 관리,보안상 문제가 발생됨.
            예) 해당 계정으로 ftp 로그인 시 / 디렉터리로 접속하여 중요 정보가 노출될 수 있음."
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    for line in `egrep "bin/.*sh" /etc/passwd`
    do
        USER=`echo $line | awk -F: '{print $1}'`
        HOMEDIR=`echo $line | awk -F: '{print $6}'`

        if [ '$HOMEDIR' == '/' ]; then
            result=$result"${USER}:${HOMEDIR}\n"
            check="N"
        else
            if [ ! -d $HOMEDIR ]; then
                result=$result"${USER}:${HOMEDIR} => 존재 하지 않음.\n"
                check="N"
            else
                result=$result"${USER}:${HOMEDIR}\n"
            fi
        fi
    done
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 


test_U_60() {
    id="U-60"
    check="Y"
    description="숨겨진 파일 및 디렉터리 검색 및 제거"
    start_time=$(test_start $id)
    result="■ 기준: 디렉토리 내에 숨겨진 파일을 확인 및 검색하여, 불필요한 파일 존재 시 삭제했을 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    find /tmp -name ".*" -ls  > hidden-file.txt
    find /home -name ".*" -ls >> hidden-file.txt
    find /usr -name ".*" -ls  >> hidden-file.txt
    find /var -name ".*" -ls  >> hidden-file.txt

    result=$result"숨겨진 파일 및 디렉토리 목록\n"
    result=$result"-----------------------\n"
    
    if [ -s hidden-file.txt ]; then
        result=$result"숨겨진 파일 및 디렉토리가 발견되지 않았습니다. (양호)"
    else
        result=$result`cat hidden-file.txt`
        check="N"
    fi
    rm -rf hidden-file.txt
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_61() {
    id="U-61"
    check="Y"
    description="ssh 원격접속 허용"
    start_time=$(test_start $id)
    result="■ 기준: SSH 서비스가 활성화 되어 있으면 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    result=$result"SSH Service\n"
    if [ `((systemctl --type=service --state=running 2>/dev/null) || (service --status-all 2>/dev/null | egrep "running|enabled" )) | egrep "ssh" | wc -l` -gt 0 ]; then
        result=$result`((systemctl --type=service --state=running 2>/dev/null) || (service --status-all 2>/dev/null | egrep "running|enabled" )) | egrep "ssh"`"\n\n"
        result=$result`(netstat -lap 2>/dev/null | grep :ssh | grep LISTEN || ss -lap | grep :ssh | grep LISTEN)`
    else
        check="N"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_62() {
    id="U-62"
    check="Y"
    description="ftp 서비스 확인"
    start_time=$(test_start $id)
    result="■ 기준: ftp 서비스가 비활성화 되어 있을 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ `((systemctl --type=service --state=running 2>/dev/null) || (service --status-all 2>/dev/null | egrep "running|enabled" )) | egrep "ftp" | wc -l` -gt 0 ]; then 
        result=$result`((systemctl --type=service --state=running 2>/dev/null) || (service --status-all 2>/dev/null | egrep "running|enabled" )) | egrep "ftp"`
        check="N"
    else
        result=$result"FTP Service Disable"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_63() {
    id="U-63"
    check="Y"
    description="ftp 계정 shell 제한"
    start_time=$(test_start $id)
    result="■ 기준: ftp 서비스가 비활성화 되어 있을 경우 양호
            ■    : ftp 서비스 사용 시 ftp 계정의 Shell을 접속하지 못하도록 설정하였을 경우 양호
            ■    : ftp 계정 쉘 확인(ftp 계정에 false 또는 nologin 설정시 양호)"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ `((systemctl --type=service --state=running 2>/dev/null) || (service --status-all 2>/dev/null | egrep "running|enabled" )) | egrep "ftp" | wc -l` -gt 0 ]; then 
        result=$result`((systemctl --type=service --state=running 2>/dev/null) || (service --status-all 2>/dev/null | egrep "running|enabled" )) | egrep "ftp"`"\n"

        if [ `cat /etc/passwd | grep ftp | wc -l` -gt 0 ]; then
            result=$result"/etc/passwd 내 ftp 계정\n"
            result=$result`cat /etc/passwd | grep ftp`

            if [ `cat /etc/passwd | grep ftp | awk -F: '$7 ~ /.*(nologin|false)/ {print $0}' | wc -l` -eq 0 ]; then
                check="N"
            fi
        fi
    else
        result=$result"FTP Service Disable"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_64() {
    id="U-64"
    check="Y"
    description="ftpusers 파일 소유자 및 권한 설정"
    start_time=$(test_start $id)
    result="■ 기준: ftpusers 파일의 소유자가 root이고, 권한이 640 이하인 경우 양호
            ■    : [FTP 종류별 적용되는 파일]
            ■    : (1)ftpd: /etc/ftpusers 또는 /etc/ftpd/ftpusers
            ■    : (2)proftpd: /etc/ftpusers 또는 /etc/ftpd/ftpusers
            ■    : (3)vsftpd: /etc/vsftpd/ftpusers, /etc/vsftpd/user_list (또는 /etc/vsftpd.ftpusers, /etc/vsftpd.user_list)"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    result=$result"FTP 서비스 활성화 여부\n"
    if [ `((systemctl --type=service --state=running 2>/dev/null) || (service --status-all 2>/dev/null | egrep "running|enabled" )) | egrep "ftp" | wc -l` -gt 0 ]; then
        result=$result`((systemctl --type=service --state=running 2>/dev/null) || (service --status-all 2>/dev/null | egrep "running|enabled" )) | egrep "ftp"`"\n\n"
        
        ServiceDIR="/etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/user_list /etc/vsftpd.user_list"
        tmp_check=0

        for line in `echo $ServiceDIR`
        do
            if [ -f $line ]; then
                tmp_check=1
                result=$result`ls -alL $line 2>/dev/null`
                if [ `stat -c "%a" $line` -gt 640 ] || [ `stat -c "%U" $line` != 'root' ]; then
                    check="N"
                fi
            fi
        done

        if [ $tmp_check == 0 ]; then
            result=$result"ftpusers 파일을 찾을 수 없습니다. (FTP 서비스 동작 시 취약)"
            check="N"
        fi
    else
        result=$result"FTP Service Disable"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_65() {
    id="U-65"
    check="Y"
    description="ftpusers 파일 설정"
    start_time=$(test_start $id)
    result="■ 기준: ftp 를 사용하지 않거나, ftp 사용시 ftpusers 파일에 root가 있을 경우 양호
            ■ : [FTP 종류별 적용되는 파일]
            ■ : (1)ftpd: /etc/ftpusers 또는 /etc/ftpd/ftpusers
            ■ : (2)proftpd: /etc/ftpusers 또는 /etc/ftpd/ftpusers
            ■ : (3)vsftpd: /etc/vsftpd/ftpusers, /etc/vsftpd/user_list (또는 /etc/vsftpd.ftpusers, /etc/vsftpd.user_list)"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    result=$result"FTP 서비스 활성화 여부\n"
    if [ `((systemctl --type=service --state=running 2>/dev/null) || (service --status-all 2>/dev/null | egrep "running|enabled" )) | egrep "ftp" | wc -l` -gt 0 ]; then
        result=$result`((systemctl --type=service --state=running 2>/dev/null) || (service --status-all 2>/dev/null | egrep "running|enabled" )) | egrep "ftp"`"\n\n"
        
        ServiceDIR="/etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/user_list /etc/vsftpd.user_list"
        tmp_check=0

        for line in `echo $ServiceDIR`
        do
            if [ -f $line ]; then
                tmp_check=1
                result=$result`echo $line`"\n"
                result=$result"--------------------------------\n"
                result=$result`cat $line | egrep -v '^\s*(#|$)'`
                if [ `cat $line | egrep -v '^\s*(#|$)' | grep root | wc -l` -eq 0 ]; then
                    check="N"
                fi
            fi
        done

        if [ $tmp_check == 0 ]; then
            result=$result"ftpusers 파일을 찾을 수 없습니다. (FTP 서비스 동작 시 취약)"
            check="N"
        fi
    else
        result=$result"FTP Service Disable"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_66() {
    id="U-66"
    check="Y"
    description="at 파일 소유자 및 권한 설정"
    start_time=$(test_start $id)
    result="■ 기준: at.allow 또는 at.deny 파일 권한이 640 이하인 경우 양호
            ■     : (at.allow 와 at.deny 파일이 모두 없는 경우 슈퍼 USER만 사용가능)"
    result=$result"\n\n■ 현황\n"
    
    # Tests Start ##
    result=$result"① at.allow 파일 권한 확인\n"
    result=$result"---------------------\n"
    if [ -f /etc/at.allow ]; then
        result=$result`ls -alL /etc/at.allow`
        result=$result`cat /etc/at.allow`
        if [ `stat -c "%a" /etc/at.allow` -gt 640 ] || [ `stat -c "%U" /etc/at.allow` != 'root' ]; then
            check="N"
        fi
    else
        result=$result"/etc/at.allow 파일이 없습니다.\n"
    fi
    
    result=$result"\n② at.deny 파일 권한 확인\n"
    result=$result"---------------------\n"
    if [ -f /etc/at.deny ]; then
        result=$result`ls -alL /etc/at.deny`
        result=$result`cat /etc/at.deny`
        if [ `stat -c "%a" /etc/at.deny` -gt 640 ] || [ `stat -c "%U" /etc/at.deny` != 'root' ]; then
            check="N"
        fi
    else
        result=$result"/etc/at.deny 파일이 없습니다."
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_67() {
    id="U-67"
    check="Y"
    description="SNMP 서비스 구동 점검"
    start_time=$(test_start $id)
    result="■ 기준: SNMP 서비스를 불필요한 용도로 사용하지 않을 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    result=$result"SNMP Service\n"
    result=$result"---------------------\n"
    if [ `(netstat -lap 2>/dev/null || ss -lap 2>/dev/null) | grep -i ":snmp" | wc -l` -gt 0 ];then 
        result=$result`(netstat -lap 2>/dev/null || ss -lap 2>/dev/null) | grep -i ":snmp"`
        check="N"
    else
        result=$result"SNMP Service Disable"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_68() {
    id="U-68"
    check="Y"
    description="SNMP 서비스 커뮤니티스트링의 복잡성 설정"
    start_time=$(test_start $id)
    result="■ 기준: SNMP Community 이름이 public, private 이 아닐 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ `(netstat -lap 2>/dev/null || ss -lap 2>/dev/null) | grep -i ":snmp" | wc -l` -gt 0 ];then 
        result=$result"SNMP Service Enabled\n\n"
        result=$result"SNMP Community String 설정 값\n"
        
        if [ -f /etc/snmpd.conf ]; then
            result=$result"● /etc/snmpd.conf 파일 설정\n"
            result=$result"-----------------------------\n"
            result=$result`cat /etc/snmpd.conf | egrep -v '^\s*(#|$)' | egrep -i "public|private|com2sec|community"`

            if [ `cat /etc/snmpd.conf | egrep -v '^\s*(#|$)' | egrep -i "public|private|com2sec|community" | wc -l` -gt 0 ]; then
                check="N"
            fi
        fi

        if [ -f /etc/snmp/snmpd.conf ]; then
            result=$result"● /etc/snmp/snmpd.conf 파일 설정\n"
            result=$result"-----------------------------\n"
            result=$result`cat /etc/snmp/snmpd.conf | egrep -v '^\s*(#|$)' | egrep -i "public|private|com2sec|community"`

            if [ `cat /etc/snmp/snmpd.conf | egrep -v '^\s*(#|$)' | egrep -i "public|private|com2sec|community" | wc -l` -gt 0 ]; then
                check="N"
            fi
        fi
        
        if [ -f /etc/snmp/conf/snmpd.conf ]; then
            result=$result"● /etc/snmp/conf/snmpd.conf 파일 설정\n"
            result=$result"-----------------------------\n"
            result=$result`cat /etc/snmp/conf/snmpd.conf | egrep -v '^\s*(#|$)' | egrep -i "public|private|com2sec|community"`

            if [ `cat /etc/snmp/conf/snmpd.conf | egrep -v '^\s*(#|$)' | egrep -i "public|private|com2sec|community" | wc -l` -gt 0 ]; then
                check="N"
            fi
        fi
        
        if [ -f /SI/CM/config/snmp/snmpd.conf ]; then
            result=$result"● /SI/CM/config/snmp/snmpd.conf 파일 설정"
            result=$result"-----------------------------\n"
            result=$result`cat /SI/CM/config/snmp/snmpd.conf | egrep -v '^\s*(#|$)' | egrep -i "public|private|com2sec|community"`

            if [ `cat /SI/CM/config/snmp/snmpd.conf | egrep -v '^\s*(#|$)' | egrep -i "public|private|com2sec|community" | wc -l` -gt 0 ]; then
                check="N"
            fi
        fi
    else
        result=$result"SNMP Service Disable"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_69() {
    id="U-69"
    check="N"
    description="로그온 시 경고 메시지 제공"
    start_time=$(test_start $id)
    result="■ 기준: /etc/issue.net과 /etc/motd 파일에 로그온 경고 메시지가 설정되어 있을 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    result=$result"● /etc/motd 파일 설정\n"
    result=$result"------------------------------------------\n"
    if [ -f /etc/motd ]; then
        if [ `cat /etc/motd | egrep -v '^\s*(#|$)' | wc -l` -gt 0 ]; then
            result=$result`cat /etc/motd | egrep -v '^\s*(#|$)'`
            check="Y"
        fi
    else
        result=$result"/etc/motd 파일이 없습니다.\n"
    fi

    result=$result"\n"
    result=$result"● /etc/issue.net 파일 설정\n"
    result=$result"------------------------------------------\n"
    if [ -f /etc/issue.net ]; then
        if [ `cat /etc/issue.net | egrep -v '^\s*(#|$)'| wc -l` -gt 0 ]; then
            result=$result$(cat /etc/issue.net | egrep -v '^\s*(#|$)' | sed -e 's/\\/\\\\/g')
            check="Y"
        else
            result=$result"경고 메시지 설정 내용이 없습니다.\n"
        fi
    else
        result=$result"/etc/issue.net 파일이 없습니다.\n"
    fi

    result=$result"\n\n"
    result=$result"● /etc/update-motd.d/99-yogiyo 파일 설정\n"
    result=$result"------------------------------------------\n"
    if [ -f /etc/update-motd.d/99-yogiyo ]; then
        if [ `cat /etc/update-motd.d/99-yogiyo | egrep -v '^\s*(#|$)' | wc -l` -gt 0 ]; then
            result=$result`cat /etc/update-motd.d/99-yogiyo | egrep -v '^\s*(#|$)'`
            check="Y"
        else
            result=$result"경고 메시지 설정 내용이 없습니다.\n"
        fi
    else
        result=$result"/etc/update-motd.d/99-yogiyo 파일이 없습니다.\n"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_70() {
    id="U-70"
    check="Y"
    description="NFS 설정 파일 접근 권한"
    start_time=$(test_start $id)
    result="■ 기준: NFS 서버 데몬이 동작하지 않거나, /etc/exports 파일의 권한이 644 이하인 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ `((systemctl --type=service --state=running 2>/dev/null) || (service --status-all 2>/dev/null | egrep "running|enabled" )) | egrep "nfs" | wc -l` -gt 1 ];then 
        check="N"
        result=$result"NFS Service Enable\n"
        result=$result`((systemctl --type=service --state=running 2>/dev/null) || (service --status-all 2>/dev/null | egrep "running|enabled" )) | egrep "nfs"`
    else
        result=$result"NFS Service Disable\n"
    fi

    result=$result"\n\n/etc/exports\n"
    result=$result"------------------------------------------\n"
    if [ -f /etc/exports ]; then
        result=$result`ls -l /etc/exports`
        if [ `stat -c "%a" /etc/exports` -gt 644 ]; then
            check="N"
        fi
    else
        result=$result"/etc/exports 파일이 없습니다."
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_71() {
    id="U-71"
    check="Y"
    description="expn, vrfy 명령어 제한"
    start_time=$(test_start $id)
    result="■ 기준: SMTP 서비스를 사용하지 않거나 noexpn, novrfy 옵션이 설정되어 있을 경우 양호"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [[ `(netstat -lap  2>/dev/null || ss -lap  2>/dev/null ) | grep :smtp | grep -v "grep" | wc -l` -gt 0 ]]; then
        result=$result"SMTP Enable\n"

        if [ `ps -ef | grep -i sendmail | grep -v grep | wc -l` -gt 0 ]; then
            result=$result"/etc/mail/sendmail.cf 파일의 옵션 확인(noexpn,novrfy,goaway)\n"
            result=$result"------------------------------------\n"
            if [ -f /etc/mail/sendmail.cf ]; then
                if [ `cat /etc/mail/sendmail.cf 2> /dev/null | egrep -v '^\s*(#|$)' | grep "O PrivacyOptions" | grep authwarnings | grep novrfy | grep noexpn | wc -l ` -ne 0 ]; then
                    result=$result"novrfy, noexpn 설정 - 양호\n"
                    result=$result`cat /etc/mail/sendmail.cf | egrep -v '^\s*(#|$)' | egrep -i "O PrivacyOptions|authwarnings|novrfy|noexpn"`
                
                elif [ `cat /etc/mail/sendmail.cf 2> /dev/null | egrep -v '^\s*(#|$)' | grep "O PrivacyOptions" | grep authwarnings | grep goaway  | wc -l ` -ne 0 ]; then
                    result=$result"goaway 설정 - 양호\n"
                    result=$result`cat /etc/mail/sendmail.cf | egrep -v '^\s*(#|$)' | egrep -i "O PrivacyOptions|authwarnings|goaway"`
                
                else
                    result=$result"noexpn, novrfy 설정 안됨 - 취약\n"
                    result=$result`cat /etc/mail/sendmail.cf 2> /dev/null | egrep -i "O PrivacyOptions|authwarnings|novrfy|noexpn|goaway"`
                fi
            else
                result=$result"/etc/mail/sendmail.cf 파일이 없습니다.\n"
            fi
        fi

        if [ `ps -ef | grep -i postfix | grep -v grep | wc -l` -gt 0 ]; then
            result=$result"/etc/postfix/main.cf 파일의 옵션 확인(disable_vrfy_command)\n"
            result=$result"------------------------------------\n"
            if [ -f /etc/postfix/main.cf ]; then
                result=$result`cat /etc/postfix/main.cf | egrep "disable_vrfy_command\s*\=s*yes"`
                if [ `cat /etc/postfix/main.cf | egrep -v '^\s*(#|$)' | egrep "disable_vrfy_command\s*=\s*yes" | wc -l ` -ne 0 ]; then
                    result=$result"novrfy, noexpn 설정 - 양호\n"
                else
                    result=$result"noexpn, novrfy 설정 안됨 - 취약\n"
                fi
            else
                result=$result"/etc/postfix/main.cf 파일이 없습니다.\n"
            fi
        fi
    else
        result=$result"SMTP Service Disable"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_72() {
    id="U-72"
    check="Y"
    description="Apache 웹서비스 정보 숨김"
    start_time=$(test_start $id)
    result="■ 기준: ServerTokens 지시자로 헤더에 전송되는 정보를 설정할 수 있음.(ServerTokens Prod 설정인 경우 양호)
            ■     : ServerTokens Prod 설정이 없는 경우 Default 설정(ServerTokens Full)이 적용됨."
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    if [ `((systemctl --type=service --state=running 2>/dev/null) || (service --status-all 2>/dev/null | egrep "running|enabled" )) | egrep -i "apache|httpd" | wc -l` -gt 0 ];then 
        if [ "$OS" == "Ubuntu" ] || [ "$OS" == "Debian" ]; then
            AP_ROOT_DIR=`apache2 -V 2>/dev/null | grep HTTPD_ROOT | awk -F= '{print $2}' | sed 's/"//g'`
            AP_CONFIG=`apache2 -V 2>/dev/null | grep SERVER_CONFIG_FILE | awk -F= '{print $2}' | sed -e 's/"//g'`
            
        else
            AP_ROOT_DIR=`httpd -V 2>/dev/null | grep HTTPD_ROOT | awk -F= '{print $2}' | sed -e 's/"//g'`
            AP_CONFIG=`httpd -V 2>/dev/null | grep SERVER_CONFIG_FILE | awk -F= '{print $2}' | sed -e 's/"//g'`
        fi
        CONFIG=$AP_ROOT_DIR/$AP_CONFIG

        if [ -f $CONFIG ]; then
            DIR_CNT=`cat $CONFIG | egrep -v '^\s*(#|$)' | egrep '<Directory ' | wc -l`
            result=$result`cat $CONFIG | egrep -v "^\s*(#|$)" | sed -n -e '/<Directory/, /<\/Directory>$/p'`

            if [ `cat $CONFIG | egrep -v '^\s*(#|$)' | egrep -i 'ServerTokens|ServerSignature' | wc -l` -lt $(( $DIR_CNT * 2 )) ]; then
                check="N"
            fi
        else
            check="-"
            result=$result"설정파일 확인 불가(수동점검)"
        fi
    else
        result=$result"Apache Service Disable"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 

test_U_73() {
    id="U-73"
    check="-"
    description="정책에 따른 시스템 로깅 설정"
    start_time=$(test_start $id)
    result="■ 기준: 로그 기록 정책이 정책에 따라 설정되어 수립되어 있는 경우
            ■    :로그 기록 정책 미수립 또는, 정책에 따라 설정되어 있지 않은 경우"
    result=$result"\n\n■ 현황\n"
    
    ## Tests Start ##
    result=$result`((systemctl --type=service --state=running 2>/dev/null) || (service --status-all 2>/dev/null | egrep "running|enabled" )) | egrep -i "syslog"`"\n\n"

    result=$result"rsyslog.conf\n"
    result=$result"---------------------------------\n"
    if [ -f /etc/rsyslog.conf ]; then
        if [ `cat /etc/rsyslog.conf /etc/rsyslog.d/* 2>/dev/null | egrep -v '^\s*(#|$)' | wc -l` -gt 0 ]; then
            result=$result`cat /etc/rsyslog.conf /etc/rsyslog.d/* 2>/dev/null | egrep -v '^\s*(#|$)'`
        else
            result=$result"/etc/rsyslog.conf 파일에 설정 내용이 없습니다.(주석, 빈칸 제외)"
            check="N"
        fi
    else
        result=$result"/etc/rsyslog.conf 파일이 없습니다."
        check="N"
    fi
    ## Tests End ##
    
    duration="$(test_finish $id $start_time)ms"
    write_result "$id" "$description" "$check" "$duration" "$result"
} 


### Main ###

## Run setup function
test_U_01
test_U_02
test_U_03
test_U_04
test_U_05
test_U_06
test_U_07
test_U_08
test_U_09
test_U_10
test_U_11
test_U_12
test_U_13
test_U_14
test_U_15
test_U_16
test_U_17
test_U_18
test_U_19
test_U_20
test_U_21
test_U_22
test_U_23
test_U_24
test_U_25
test_U_26
test_U_27
test_U_28
test_U_29
test_U_30
test_U_31
test_U_32
test_U_33
test_U_34
test_U_35
test_U_36
test_U_37
test_U_38
test_U_39
test_U_40
test_U_41
test_U_42
test_U_43
test_U_44
test_U_45
test_U_46
test_U_47
test_U_48
test_U_49
test_U_50
test_U_51
test_U_52
test_U_53
test_U_54
test_U_55
test_U_56
test_U_57
test_U_58
test_U_59
test_U_60
test_U_61
test_U_62
test_U_63
test_U_64
test_U_65
test_U_66
test_U_67
test_U_68
test_U_69
test_U_70
test_U_71
test_U_72
test_U_73

#-----------------------수정 시작 부분 입니다!------------------------
# --- 작업 완료 후 jq 삭제 시작 ---
echo "Cleaning up: uninstalling jq..."

# jq가 설치되어 있는지 먼저 확인
if command -v jq &>/dev/null; then
    # OS를 감지하여 jq 삭제
    if command -v apt-get &>/dev/null; then
        # Debian/Ubuntu
        sudo apt-get remove -y jq
    elif command -v yum &>/dev/null; then
        # Amazon Linux, CentOS, RHEL
        sudo yum remove -y jq
    else
        echo "Could not find a known package manager to uninstall jq." >&2
    fi
    echo "jq has been uninstalled."
else
    echo "jq was not found, skipping uninstallation."
fi
# --- jq 삭제 끝 ---
#-----------------------수정 끝 부분 입니다!--------------------------