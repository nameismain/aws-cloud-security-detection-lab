# AWS Cloud Security Detection Lab
AWS 환경에서 자주 발생하는 클라우드 오설정을 시나리오별로 정의하고, 각 오설정이 어떤 보안 위협으로 이어지는지 탐지 코드와 문서로 검증하는 보안 실습 프로젝트입니다.

이 프로젝트는 단순한 인프라 구성 실습이 아니라, 클라우드 보안 운영에서 필요한 다음 흐름을 직접 구현하는 것을 목표로 합니다.

    오설정 식별
    -> 위협 시나리오 정의
    -> 로그 또는 설정 데이터 분석
    -> 탐지 로직 구현
    -> 결과 리포트 작성
    -> 개선 권고 도출

## 목적
클라우드 보안에서 중요한 것은 위험한 설정을 찾는 것에서 끝나지 않습니다.
이 프로젝트는 다음 질문에 답할 수 있도록 설계합니다.

* 어떤 클라우드 설정이 위험한가?
* 그 설정은 어떤 공격 표면을 만드는가?
* 어떤 로그 또는 설정 데이터로 확인할 수 있는가?
* 어떤 기준으로 탐지할 수 있는가?
* 오탐 가능성은 무엇인가?
* 어떻게 개선해야 하는가?

## 탐지 시나리오

| 번호 | 시나리오 | 탐지 대상 | 주요 데이터 | 상태 |
| -- | -- | -- | -- | -- |
| 01 | Public SSH Exposure | SSH Brute Force | Security Group, auth.log | 진행 중 |
| 02 | Public S3 Bucket | 공개 버킷 및 객체 접근 | S3 Policy, CloudTrail | 예정 |
| 03 | Overprivileged IAM | 과도한 IAM 권한 | IAM Policy | 예정 |
| 04 | CloudTrail Disabled	| 로깅 중단 및 감사 회피 | CloudTrail Event	| 예정 |
| 05 | Public Database Port | DB 포트 인터넷 노출 | Security Group | 예정 |

## 현재 진행 단계
현재는 첫 번째 시나리오인 Public SSH Exposure를 구현하는 단계입니다.
이 시나리오는 공개된 SSH 포트가 Brute Force 공격 표면이 될 수 있다는 점을 다룹니다.

## 저장소 구조
```
aws-cloud-security-detection-lab/
├── README.md
├── terraform/
├── scenarios/
│   ├── 01-public-ssh/
│   ├── 02-public-s3/
│   ├── 03-overprivileged-iam/
│   ├── 04-cloudtrail-disabled/
│   └── 05-public-database/
├── detectors/
├── sigma-rules/
├── reports/
└── docs/
    ├── architecture.md
    ├── detection-standard.md
    ├── scenario-design.md
    └── roadmap.md
```

## 문서
자세한 내용은 아래 문서에서 관리합니다.

* [Architecture](./docs/architecture.md)
* [Detection Standard](./docs/detection-standard.md)
* [Scenario Design](./docs/scenario-design.md)
* [Roadmap](./docs/roadmap.md)

## 실행 예시
첫 번째 시나리오의 예상 실행 방식은 다음과 같습니다.
```
python detectors/public_ssh.py scenarios/01-public-ssh/sample.log
```
예상 출력 형식은 다음과 같습니다.
```
[HIGH] SSH Brute Force 의심
Resource: EC2 SSH Authentication Log
Condition: 동일한 출발지 IP에서 5분 이내 로그인 실패 5회 이상 발생
Risk: 공개된 SSH 포트를 대상으로 한 Brute Force 가능성
Recommendation: SSH 접근을 신뢰 IP 또는 VPN 대역으로 제한
```