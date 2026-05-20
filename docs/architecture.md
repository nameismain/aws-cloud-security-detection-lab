# 아키텍처 문서

## 개요
이 문서는 Fintech Cloud Threat Detection Lab의 전체 아키텍처를 설명합니다.

## 설계 목표
이 아키텍처의 목표는 다음과 같습니다.

1. 클라우드 오설정을 시나리오 단위로 분리한다.
2. 각 시나리오에서 위험 설정과 예상 위협을 명확히 연결한다.
3. 탐지에 필요한 데이터 유형을 정의한다.
4. 설정 기반 탐지와 로그 기반 탐지를 함께 다룬다.
5. 탐지 결과를 사람이 이해할 수 있는 리포트로 정리한다.
6. 향후 SIEM, Sigma, Terraform 기반 실습 환경으로 확장할 수 있게 구성한다.

## 전체 구조
```
Cloud Misconfiguration Scenarios
    |
    |-- 01 Public SSH Exposure
    |-- 02 Public S3 Bucket
    |-- 03 Overprivileged IAM
    |-- 04 CloudTrail Disabled
    |-- 05 Public Database Port
    |
Input Data Layer
    |
    |-- Security Group Rule
    |-- IAM Policy JSON
    |-- S3 Bucket Policy
    |-- CloudTrail Event
    |-- SSH auth.log
    |
Detection Layer
    |
    |-- public_ssh.py
    |-- public_s3.py
    |-- overprivileged_iam.py
    |-- cloudtrail_disabled.py
    |-- public_database.py
    |
Analysis Layer
    |
    |-- 위험도 분류
    |-- 오탐 가능성 검토
    |-- 탐지 근거 정리
    |
Reporting Layer
    |
    |-- 시나리오별 result.md
    |-- summary-report.md
    |-- 개선 권고
    |
Future Extension
    |
    |-- Terraform AWS Lab
    |-- Sigma Rules
    |-- ELK or OpenSearch
    |-- Slack Alert
```

## 계층별 설명

### 1. Scenario Layer

Scenario Layer는 프로젝트의 중심입니다.
각 시나리오는 하나의 클라우드 오설정 또는 위험 행위를 다룹니다.
시나리오는 단순히 취약점 이름을 나열하는 것이 아니라, 다음 항목을 함께 설명합니다.

    위험한 설정
    예상 위협
    탐지 데이터
    탐지 기준
    오탐 가능성
    개선 권고

시나리오 목록은 다음과 같습니다.

| 번호 | 시나리오 | 핵심 위험 |
| -- | -- | -- |
| 01 | Public SSH Exposure | SSH Brute Force 가능성 |
| 02 | Public S3 Bucket | 데이터 유출 가능성 |
| 03 | Overprivileged IAM | 권한 남용 및 계정 장악 위험 |
| 04 | CloudTrail Disabled | 감사 회피 및 추적 불가 |
| 05 | Public Database Port	DB | 직접 접근 및 데이터 유출 위험

### 2. Input Data Layer
Input Data Layer는 탐지 로직이 분석할 데이터를 의미합니다.

초기 단계에서는 실제 AWS 환경을 바로 사용하지 않고, 샘플 로그와 샘플 설정 파일을 사용합니다. 이렇게 하면 비용과 보안 위험을 줄이면서 탐지 로직을 먼저 검증할 수 있습니다.

| 데이터 유형 | 사용 시나리오 | 설명 |
| -- | -- | -- |
| SSH auth.log | Public SSH Exposure | SSH 로그인 실패 이벤트 |
| Security Group JSON | Public SSH, Public Database | 포트와 Source 허용 범위|
| S3 Bucket Policy | Public S3 Bucket | 버킷 접근 정책 |
| IAM Policy JSON | Overprivileged IAM | 권한 범위와 리소스 범위 |
| CloudTrail Event | Public S3, CloudTrail Disabled | AWS API 호출 기록 |

### 3. Detection Layer
Detection Layer는 각 시나리오의 탐지 로직을 구현하는 영역입니다. 각 탐지 스크립트는 특정 시나리오의 샘플 데이터를 입력으로 받아 위험 조건을 확인하고, 표준화된 결과를 출력합니다.

| 탐지 스크립트 | 역할 |
| -- | -- |
| public_ssh.py | SSH 로그인 실패 반복 탐지 |
| public_s3.py | S3 공개 정책 및 객체 접근 이벤트 탐지 |
| verprivileged_iam.py | 과도한 IAM 권한 탐지 |
| cloudtrail_disabled.py | CloudTrail 로깅 중단 이벤트 탐지 |
| public_database.py | DB 및 관리 포트 인터넷 노출 탐지 |

탐지 결과는 가능한 한 다음 형식으로 통일합니다.

    [위험도] 탐지명
    Resource: 영향을 받는 리소스
    Condition: 탐지된 조건
    Risk: 예상 위험
    Recommendation: 개선 권고

### 4. Analysis Layer
Analysis Layer는 탐지 결과를 해석하는 영역입니다. 탐지 결과가 나왔다고 해서 항상 실제 사고라고 판단할 수는 없습니다. 따라서 각 결과에 대해 위험도와 오탐 가능성을 함께 검토합니다.

분석 항목은 다음과 같습니다.

    어떤 조건이 탐지되었는가?
    왜 위험한가?
    실제 공격 가능성은 어느 정도인가?
    정상 운영 상황에서 발생할 수 있는가?
    추가로 확인해야 할 로그는 무엇인가?
    어떤 개선 조치가 필요한가?

### 5. Reporting Layer
Reporting Layer는 탐지 결과와 분석 내용을 문서화하는 영역입니다.
각 시나리오는 자체 결과 파일을 가집니다.

    scenarios/01-public-ssh/result.md
    scenarios/02-public-s3/result.md
    scenarios/03-overprivileged-iam/result.md
    scenarios/04-cloudtrail-disabled/result.md
    scenarios/05-public-database/result.md

최종적으로는 전체 시나리오를 요약하는 종합 리포트를 작성합니다.

    reports/summary-report.md

리포트에는 다음 내용이 포함됩니다.

* 탐지된 위험 조건
* 영향을 받는 리소스
* 탐지 근거
* 위험도
* 오탐 가능성
* 개선 권고
* 향후 보완 방향

## 설정 기반 탐지와 로그 기반 탐지
이 프로젝트의 탐지는 크게 두 가지 방식으로 나뉩니다.

| 탐지 방식 | 설명 | 예시 |
| -- | -- | -- |
| 설정 기반 탐지 | 리소스 설정 자체를 분석하여 위험 여부 판단 | Public SSH, Public S3, Overprivileged IAM |
| 로그 기반 탐지 | 발생한 이벤트 로그를 분석하여 이상 행위 판단 | SSH Brute Force, CloudTrail StopLogging, GetObject 이벤트 증가 |

두 방식은 서로 분리된 것이 아니라 연결됩니다.
예를 들어 Public SSH Exposure는 다음 두 관점을 모두 가지는데, 이 연결이 프로젝트의 핵심입니다.

    설정 기반 탐지:
    Security Group에서 SSH 22번 포트가 0.0.0.0/0으로 열려 있는지 확인
    
    로그 기반 탐지:
    동일 IP에서 SSH 로그인 실패가 반복되는지 확인

## Terraform 계층
Terraform은 향후 실제 AWS 실습 환경을 생성하기 위한 계층입니다.

초기에는 샘플 데이터를 기반으로 탐지 로직을 먼저 검증합니다. 이후 Terraform을 사용하여 통제된 AWS 실습 환경을 구성합니다.

Terraform으로 생성할 수 있는 리소스는 다음과 같습니다.

| 리소스 | 역할 |
| -- | -- |
| VPC | 격리된 실습 네트워크 |
| Subnet | 리소스 배치 영역 |
| Internet Gateway | 인터넷 연결 구성 |
| Route Table | 트래픽 경로 제어 |
| Security Group | 접근 제어 규칙 실습 |
| EC2 | SSH 로그 발생 대상 |
| S3 Bucket | 공개 버킷 탐지 실습 |
| IAM Policy | 권한 점검 실습 |
| CloudTrail | AWS API 이벤트 수집 |

## Sigma 및 SIEM 확장
Python 탐지 코드로 검증한 일부 로직은 Sigma 룰로 변환합니다. 우선 변환 대상은 다음과 같습니다.

    SSH Brute Force
    CloudTrail StopLogging

Sigma 룰로 변환하면 ELK, OpenSearch, Splunk 같은 SIEM 환경으로 확장하기 쉬워집니다.

향후 확장 구조는 다음과 같습니다.
```
Sample Log
    |
Sigma Rule
    |
SIEM Backend
    |
Dashboard
    |
Alert
```

## 알림 및 대응 계층
초기 프로젝트에서는 실제 차단이나 리소스 삭제 같은 자동 대응을 수행하지 않습니다. 대신 Dry Run 방식으로 대응 권고를 출력합니다.

예상 출력은 다음과 같습니다.

    Recommended Action:
    - Restrict SSH access to trusted IP ranges.
    - Review recent failed login attempts.
    - Disable password authentication if possible.
    - Monitor the source IP for repeated attempts.

자동 대응을 바로 수행하지 않는 이유는 다음과 같습니다.

* 오탐으로 정상 접근을 차단할 수 있음
* 운영 중인 리소스에 영향을 줄 수 있음
* 탐지 기준 검증이 먼저 필요함
* 대응 전 사람의 검토가 필요함