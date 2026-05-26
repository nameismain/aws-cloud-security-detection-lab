# 프로젝트 로드맵

## 개요
이 문서는 AWS Cloud Security Detection Lab의 단계별 구현 계획을 정리한 문서입니다.

이 프로젝트는 AWS 환경에서 자주 발생하는 클라우드 오설정을 시나리오별로 정의하고, 각 오설정이 어떤 보안 위협으로 이어지는지 탐지 코드와 문서로 검증하는 것을 목표로 합니다.

초기에는 공개 SSH 포트로 인한 Brute Force 탐지 시나리오를 구현하고, 이후 S3 공개 설정, IAM 권한 과다 부여, CloudTrail 비활성화, Public Database Port와 같은 주요 클라우드 오설정 탐지로 확장합니다.

프로젝트의 핵심 방향은 다음과 같습니다.
```
클라우드 오설정 식별
-> 위협 시나리오 정의
-> 로그 또는 설정 데이터 분석
-> 탐지 로직 구현
-> 탐지 결과 리포트 작성
-> 오탐 가능성 검토
-> 개선 권고 도출
```

## 전체 구현 전략

이 프로젝트는 한 번에 모든 기능을 완성하는 방식으로 진행하지 않습니다.
먼저 하나의 시나리오를 끝까지 완성한 뒤, 같은 구조를 다른 시나리오에 반복 적용합니다.

각 시나리오는 다음 구성 요소를 갖습니다.
```
- 시나리오 문서
- 탐지 기준 문서
- 샘플 로그 또는 샘플 설정 데이터
- 탐지 코드
- 탐지 결과 리포트
- 개선 권고
```

공통 구현 흐름은 다음과 같습니다.

    1. 위험한 클라우드 설정을 정의한다.
    2. 해당 설정이 어떤 위협으로 이어지는지 설명한다.
    3. 탐지에 필요한 데이터 유형을 정한다.
    4. 샘플 데이터를 만든다.
    5. 탐지 로직을 구현한다.
    6. 탐지 결과를 리포트로 정리한다.
    7. 오탐 가능성과 개선 방향을 문서화한다.

---

### Phase 1. 프로젝트 구조 정리

**목표**

프로젝트를 단일 SSH Brute Force 탐지 프로젝트에서 클라우드 오설정 탐지 시나리오 모음으로 확장할 수 있도록 구조를 정리합니다.

**구현 항목**

    scenarios 디렉터리 추가
    시나리오별 하위 디렉터리 생성
    detectors 디렉터리 정리
    공통 문서 추가
    README.md 작성
    로드맵과 탐지 기준 문서 작성

--- 

### Phase 2. [Scenario 01: Public SSH Exposure]

**목표**

공개된 SSH 포트로 인해 발생할 수 있는 Brute Force 공격 시나리오를 구현합니다.
이 단계는 프로젝트의 첫 번째 완성 시나리오입니다. 이후 다른 시나리오를 만들 때 기준이 되는 템플릿 역할을 합니다.

**위험한 설정**

Security Group에서 TCP 22번 포트가 0.0.0.0/0으로 열려 있음

**예상 위협**

외부 공격자가 인터넷을 통해 SSH 접속을 반복적으로 시도할 수 있음

**탐지 데이터**

    Security Group 설정
    SSH 인증 로그
    sample auth.log

**탐지 기준**

    5분 이내 5회 실패
    + 시도 계정명 개수
    + 기본 계정명 사용 여부
    + 실패 이후 성공 로그인 여부
    + 허용 IP 여부
    + Security Group SSH 공개 여부

**구현 항목**

    Public SSH Exposure 시나리오 문서 작성
    샘플 SSH 인증 로그 작성
    SSH 로그인 실패 이벤트 파싱
    출발지 IP 추출
    시간 윈도우 기반 실패 횟수 집계
    탐지 결과 출력
    탐지 결과 리포트 작성
    Security Group의 SSH 공개 설정과 탐지 결과 연결

**산출물**

    scenarios/01-public-ssh/sample.log
    scenarios/01-public-ssh/result.md
    detectors/public_ssh.py

**완료 기준**

샘플 로그에서 동일 IP의 반복적인 SSH 로그인 실패를 탐지하고, 해당 결과를 리포트로 설명할 수 있어야 합니다.

### Phase 3. [Scenario 02: Public S3 Bucket]

**목표**

S3 버킷이 외부에 공개되어 데이터 유출 위험이 발생하는 시나리오를 구현합니다.

**위험한 설정**

S3 Public Access Block이 비활성화되어 있거나,
Bucket Policy에서 `Principal "*"` 접근을 허용함

**예상 위협**

외부 사용자가 버킷 객체를 조회하거나 다운로드할 수 있음,
민감 데이터가 의도치 않게 노출될 수 있음

**탐지 데이터**

    S3 Bucket Policy
    S3 Public Access Block 설정
    CloudTrail GetObject 이벤트

**탐지 기준**

Bucket Policy에서 `Principal "*"` 접근이 허용되어 있거나,
Public Access Block이 비활성화된 경우 위험 설정으로 판단한다.

**추가 로그 기반 탐지 기준**

외부 IP에서 특정 버킷에 대한 GetObject 이벤트가 반복적으로 발생하면
비정상 객체 접근 가능성을 검토한다.

**구현 항목**

    Public S3 Bucket 시나리오 문서 작성
    샘플 Bucket Policy 작성
    샘플 CloudTrail 이벤트 작성
    Public 접근 허용 여부 탐지
    GetObject 이벤트 분석 기준 정리
    탐지 결과 리포트 작성

**산출물**

    scenarios/02-public-s3/sample-cloudtrail.json
    scenarios/02-public-s3/result.md
    detectors/public_s3.py

**완료 기준**

샘플 정책 또는 샘플 이벤트를 기반으로 S3 공개 위험을 탐지하고, 어떤 데이터 유출 위험으로 이어질 수 있는지 설명할 수 있어야 합니다.

---

### Phase 4. [Scenario 03: Overprivileged IAM]

**목표**

IAM 사용자 또는 Role에 과도한 권한이 부여된 상황을 탐지합니다.

**위험한 설정**

AdministratorAccess 정책이 연결되어 있음,
`Action "*"` 또는 `Resource "*"`가 포함된 광범위한 정책이 사용됨

**예상 위협**

계정 또는 Access Key 탈취 시 공격자가 AWS 리소스 전반을 조작할 수 있음,
권한 상승, 로그 삭제, 데이터 접근, 리소스 생성 등의 행위로 이어질 수 있음

**탐지 데이터**

    IAM Policy JSON
    IAM User Policy Attachment
    IAM Role Policy Attachment
    CloudTrail IAM API 이벤트

**탐지 기준**

IAM Policy에서 `Action "*"`가 허용되어 있거나,
`Resource "*"`가 과도하게 사용되거나,
AdministratorAccess가 연결된 경우 위험 권한으로 판단한다.

**구현 항목**

    Overprivileged IAM 시나리오 문서 작성
    샘플 IAM Policy 작성
    Action “*” 탐지
    Resource “*” 탐지
    AdministratorAccess 연결 여부 탐지
    위험도 분류
    최소 권한 개선안 작성

**산출물**

    scenarios/03-overprivileged-iam/sample-policy.json
    scenarios/03-overprivileged-iam/result.md
    detectors/overprivileged_iam.py

**완료 기준**

샘플 IAM 정책에서 과도한 권한을 탐지하고, 왜 최소 권한 원칙에 어긋나는지 설명할 수 있어야 합니다.

---

### Phase 5. [Scenario 04: CloudTrail Disabled]

**목표**

CloudTrail 로깅 중단 또는 삭제 이벤트를 탐지하여 감사 회피 가능성을 분석합니다.

**위험 행위**

    StopLogging
    DeleteTrail
    UpdateTrail
    PutEventSelectors

**예상 위협**

    공격자가 AWS 계정 내 행위 추적을 어렵게 만들 수 있음
    침해 사고 분석에 필요한 감사 로그가 누락될 수 있음

**탐지 데이터**

    CloudTrail Event
    AWS API 호출 로그

**탐지 기준**

CloudTrail 이벤트에서 StopLogging 또는 DeleteTrail API 호출이 발생하면,
감사 회피 가능성이 있는 고위험 이벤트로 판단한다.

**구현 항목**

    CloudTrail Disabled 시나리오 문서 작성
    샘플 CloudTrail 이벤트 작성
    StopLogging 이벤트 탐지
    DeleteTrail 이벤트 탐지
    이벤트 수행 주체 추출
    탐지 결과 리포트 작성
    대응 권고 작성

**산출물**

    scenarios/04-cloudtrail-disabled/sample-cloudtrail.json
    scenarios/04-cloudtrail-disabled/result.md
    detectors/cloudtrail_disabled.py
    sigma-rules/cloudtrail_stop_logging.yml

**완료 기준**

샘플 CloudTrail 이벤트에서 로깅 중단 행위를 탐지하고, 해당 이벤트가 왜 방어 회피 행위로 볼 수 있는지 설명할 수 있어야 합니다.

### Phase 6. [Scenario 05: Public Database Port]

**목표**

데이터베이스 또는 관리형 서비스 포트가 인터넷 전체에 노출된 설정을 탐지합니다.

**위험한 설정**

Security Group에서 DB 관련 포트가 0.0.0.0/0으로 열려 있음

**주요 위험 포트**

| 포트 | 서비스 | 위험 |
| -- | -- | -- |
| 3306 | MySQL | DB 직접 접근 가능 |
| 5432 | PostgreSQ | DB 직접 접근 가능|
| 6379 | Redis | 인증 미흡 시 데이터 접근 가능 |
| 9200 | Elasticsearch | 검색 데이터 또는 로그 노출 가능 |
| 5601 | Kibana | 대시보드 노출 가능 |
| 27017 | MongoDB | DB 직접 접근 가능 |
| 3389 | RDP | 윈도우 원격 접속 공격 가능 |

**예상 위협**

외부 공격자가 데이터베이스 또는 관리 서비스에 직접 접근을 시도할 수 있음,
인증 설정이 약할 경우 데이터 유출 또는 서비스 장악으로 이어질 수 있음

**탐지 데이터**

    Security Group Inbound Rule
    RDS Public Access 설정
    네트워크 접근 로그

**탐지 기준**

위험 포트가 0.0.0.0/0 또는 ::/0으로 열려 있으면
Public Database Port 노출로 판단한다.

**구현 항목**

    Public Database Port 시나리오 문서 작성
    샘플 Security Group JSON 작성
    위험 포트 목록 정의
    Inbound Rule 분석
    Public Source 탐지
    위험도 분류
    개선 권고 작성

**산출물**

    scenarios/05-public-database/sample-security-group.json
    scenarios/05-public-database/result.md
    detectors/public_database.py

**완료 기준**

샘플 Security Group 설정에서 위험 포트의 인터넷 노출 여부를 탐지하고, 서비스별 위험을 설명할 수 있어야 합니다.

---

### Phase 7. 공통 탐지 실행 방식 정리

**목표**

시나리오별 탐지 스크립트를 일관된 방식으로 실행할 수 있도록 정리합니다.

**구현 항목**

    detectors 디렉터리 구조 정리
    각 탐지 스크립트의 입력 파일 인자 통일
    출력 형식 표준화
    위험도 표기 통일
    공통 실행 예시 작성

**표준 출력 형식**

    [위험도] 탐지명
    Resource: 영향을 받는 리소스
    Condition: 탐지된 조건
    Risk: 예상 위험
    Recommendation: 개선 권고

**산출물**

    detectors/public_ssh.py
    detectors/public_s3.py
    detectors/overprivileged_iam.py
    detectors/cloudtrail_disabled.py
    detectors/public_database.py

**완료 기준**

각 탐지 스크립트가 서로 다른 시나리오를 다루더라도 출력 형식과 문서 구조가 일관되어야 합니다.

---

### Phase 8. Sigma 룰 및 SIEM 확장

**목표**

일부 탐지 로직을 Sigma 룰로 변환하고, 향후 SIEM 연동이 가능하도록 준비합니다.

**우선 변환 대상**

    SSH Brute Force
    CloudTrail StopLogging

**구현 항목**

    Sigma 룰 작성
    로그 소스 정의
    탐지 조건 정의
    False Positive 정리
    MITRE ATT&CK 태그 추가
    ELK 또는 OpenSearch 연동 계획 작성

**산출물**

    sigma-rules/ssh_bruteforce.yml
    sigma-rules/cloudtrail_stop_logging.yml
    docs/detection-standard.md
    reports/summary-report.md

**완료 기준**

최소 2개의 시나리오가 Sigma 룰로 표현되어야 하며, 각 룰의 탐지 목적과 오탐 가능성이 문서화되어야 합니다.

---

### Phase 9. Terraform 기반 실습 환경 확장

**목표**

샘플 데이터 기반 탐지를 실제 AWS 실습 환경으로 확장합니다.

**구현 항목**

    VPC 생성
    Public Subnet 생성
    Security Group 생성
    EC2 생성
    S3 버킷 테스트 환경 구성
    IAM 테스트 정책 구성
    CloudTrail 활성화
    VPC Flow Logs 검토

**산출물**

    terraform/provider.tf
    terraform/variables.tf
    terraform/main.tf
    terraform/outputs.tf
    docs/architecture.md

**완료 기준**

Terraform으로 통제된 AWS 실습 환경을 구성하고, 각 시나리오와 연결되는 리소스를 안전하게 생성 및 제거할 수 있어야 합니다.

---

### Phase 10. 최종 리포트 작성

**목표**

각 시나리오의 탐지 결과와 학습 내용을 하나의 종합 리포트로 정리합니다.

**구현 항목**

    시나리오별 탐지 결과 요약
    위험도별 분류
    탐지 데이터 정리
    오탐 가능성 비교
    개선 권고 정리
    향후 확장 계획 작성

**산출물**

    reports/summary-report.md

**완료 기준**

프로젝트를 처음 보는 사람이 종합 리포트만 읽어도 다음 내용을 이해할 수 있어야 합니다.

    어떤 클라우드 오설정을 다루었는가
    각 오설정이 왜 위험한가
    어떤 데이터로 탐지했는가
    탐지 결과는 무엇인가
    오탐 가능성은 무엇인가
    어떤 개선 조치가 필요한가

## 최종 목표
이 프로젝트의 최종 목표는 클라우드 보안 운영 관점에서 다음 질문에 답할 수 있는 포트폴리오를 만드는 것입니다.

    어떤 클라우드 설정이 위험한가?
    그 설정은 어떤 공격 표면을 만드는가?
    그 위험은 어떤 로그 또는 설정 데이터로 확인할 수 있는가?
    어떤 기준으로 탐지할 수 있는가?
    탐지 결과는 어떻게 해석해야 하는가?
    오탐 가능성은 무엇인가?
    어떤 개선 조치가 필요한가?