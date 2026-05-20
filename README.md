# Fintech Cloud Threat Detection Lab

AWS 기반 핀테크 인프라를 가정하고, 클라우드와 서버 로그를 분석해 보안 위협을 탐지하는 프로젝트입니다.

초기 버전은 SSH Brute Force 탐지에 집중합니다. 이후 CloudTrail, VPC Flow Logs, S3, IAM 로그를 활용해 클라우드 위협 탐지로 확장합니다.

## Goal

이 프로젝트의 목표는 단순한 인프라 배포가 아니라, 실제 보안 관제 흐름에 가까운 탐지 파이프라인을 구현하는 것입니다.

주요 목표는 다음과 같습니다.

- AWS 기반 실습 인프라 구성
- Linux 인증 로그 기반 SSH Brute Force 탐지
- CloudTrail 기반 IAM 이벤트 탐지
- S3 Public Exposure 탐지
- VPC Flow Logs 기반 비정상 네트워크 통신 탐지
- 탐지 결과를 구조화된 JSON으로 출력
- 탐지 룰과 사고 대응 절차 문서화

## Architecture

```text
[Attacker]
    |
    v
[Internet]
    |
    v
[Security Group]
    |
    v
[EC2 Instance]
    |
    v
[/var/log/auth.log]
    |
    v
[Python Detection Engine]
    |
    v
[Security Alert]
    |
    v
[Incident Report]
```

확장 구조:

```text
AWS Account
├── VPC
│   ├── EC2
│   └── VPC Flow Logs
├── CloudTrail
├── S3
├── IAM
└── Detection Engine
```

## Project Structure

```text
fintech-cloud-threat-detection-lab/
├── README.md
├── terraform/
├── scripts/
│   └── detect_ssh_bruteforce.py
├── sample-logs/
│   └── auth.log
├── detection-rules/
│   └── ssh-bruteforce.md
├── reports/
└── architecture/
```

## Current Scope

### MVP 1: SSH Brute Force Detection

현재 구현 범위는 Linux 인증 로그에서 SSH 로그인 실패를 분석하고, 동일 IP에서 반복된 실패가 발생하면 보안 이벤트로 탐지하는 것입니다.

탐지 기준:

```text
같은 출발지 IP에서 SSH 로그인 실패가 5회 이상 발생하면 HIGH severity alert 생성
```

예상 탐지 결과:

```json
[
  {
    "type": "SSH_BRUTE_FORCE",
    "source_ip": "203.0.113.10",
    "failed_count": 5,
    "severity": "HIGH",
    "recommendation": "Investigate the source IP and restrict SSH access"
  }
]
```

## Detection Scenarios

| Scenario | Data Source | Status |
|---|---|---|
| SSH Brute Force | Linux auth.log | In Progress |
| Suspicious IAM Policy Change | CloudTrail | Planned |
| S3 Public Exposure | CloudTrail / S3 | Planned |
| Abnormal Outbound Traffic | VPC Flow Logs | Planned |
| Web Attack Pattern | AWS WAF Logs | Planned |

## How to Run

```bash
python3 scripts/detect_ssh_bruteforce.py
```

## Terraform

Terraform 코드는 AWS 실습 인프라 구성을 위해 사용합니다.

```bash
cd terraform
terraform init
terraform plan
```

초기 단계에서는 비용 발생을 방지하기 위해 `terraform apply`보다 `terraform plan`을 먼저 확인합니다.

## Security Notes

이 저장소에는 민감 정보를 포함하지 않습니다.

업로드 금지 항목:

- AWS Access Key
- AWS Secret Access Key
- `.pem` 개인 키
- `.env` 파일
- Terraform state 파일
- 실제 계정 ID
- 실제 서비스 로그

## Roadmap

- [ ] 프로젝트 기본 구조 생성
- [ ] SSH Brute Force 샘플 로그 작성
- [ ] SSH Brute Force 탐지 스크립트 구현
- [ ] 탐지 룰 문서화
- [ ] Terraform 기반 EC2 실습 환경 구성
- [ ] CloudTrail 로그 수집
- [ ] IAM 이벤트 탐지 추가
- [ ] S3 Public Exposure 탐지 추가
- [ ] VPC Flow Logs 기반 네트워크 탐지 추가
- [ ] Slack 알림 또는 Dry Run 대응 자동화 추가