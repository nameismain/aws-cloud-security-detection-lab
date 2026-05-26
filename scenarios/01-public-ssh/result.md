### 실행 방법
```
python3 detectors/public_ssh.py scenarios/01-public-ssh/sample.log \
  --security-group scenarios/01-public-ssh/sample-security-group.json \
  --allowlist 10.10.10.10/32
```

### 실행 결과
```
[CRITICAL] Public SSH Exposure with Brute Force Indicators
Resource: SSH Service
Source IP: 203.0.113.10
Allowed IP: False
SSH Publicly Exposed: True
Failed Count: 6
Unique User Count: 6
Usernames: admin, ec2-user, oracle, root, test, ubuntu
Default Usernames: admin, ec2-user, oracle, root, test, ubuntu
Success After Failure: True
Success Username: ubuntu
Success Time: 2026-05-20 10:06:10
Window: 2026-05-20 10:00:01 ~ 2026-05-20 10:05:01
Condition: 5분 이내 동일 출발지 IP에서 SSH 로그인 실패 5회 이상 발생
Risk: Security Group에서 SSH 포트가 인터넷 전체에 공개되어 있습니다. 출발지 IP가 허용 목록에 포함되어 있지 않습니다. 여러 계정명으로 SSH 로그인을 시도했습니다. 기본 계정명 또는 추측하기 쉬운 계정명이 사용되었습니다: admin, ec2-user, oracle, root, test, ubuntu 반복 실패 이후 동일 IP에서 성공 로그인이 발생했습니다.
Recommendation: SSH 접근 대상을 신뢰 IP 또는 VPN 대역으로 제한하고, 비밀번호 인증을 비활성화하며, SSH Key 기반 인증과 로그 모니터링을 적용해야 합니다.
--------------------------------------------------------------------------------
[LOW] Public SSH Exposure with Brute Force Indicators
Resource: SSH Service
Source IP: 10.10.10.10
Allowed IP: True
SSH Publicly Exposed: True
Failed Count: 5
Unique User Count: 1
Usernames: ubuntu
Default Usernames: ubuntu
Success After Failure: False
Window: 2026-05-20 10:40:01 ~ 2026-05-20 10:45:01
Condition: 5분 이내 동일 출발지 IP에서 SSH 로그인 실패 5회 이상 발생
Risk: Security Group에서 SSH 포트가 인터넷 전체에 공개되어 있습니다. 출발지 IP가 허용 목록에 포함되어 있어 운영자 실수 가능성이 있습니다. 기본 계정명 또는 추측하기 쉬운 계정명이 사용되었습니다: ubuntu
Recommendation: SSH 접근 대상을 신뢰 IP 또는 VPN 대역으로 제한하고, 비밀번호 인증을 비활성화하며, SSH Key 기반 인증과 로그 모니터링을 적용해야 합니다.
--------------------------------------------------------------------------------
```