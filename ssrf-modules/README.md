# SSRF Fuzzer

크롤러 결과를 기반으로 한 지능형 SSRF(Server-Side Request Forgery) 퍼징 도구

## 기능

- **크롤러 연동**: 기존 크롤러 JSON 결과를 입력으로 사용
- **지능형 타겟 추출**: SSRF 가능성이 높은 엔드포인트와 파라미터 자동 식별
- **연구 기반 페이로드**: PortSwigger 연구를 기반으로 한 다양한 우회 기법
- **적응형 학습**: Dalfox 스타일의 응답 기반 페이로드 진화
- **멀티레이어 탐지**: 타이밍, 패턴, OOB, 컨텍스트 기반 4단계 탐지
- **OOB Collaborator**: 블라인드 SSRF 탐지를 위한 DNS/HTTP 서버

## 설치

```bash
# 의존성 설치
pip install -r requirements.txt

# 권한 설정 (DNS 서버 실행을 위해 root 권한 필요)
sudo python main.py crawler_results.json
```

## 사용법

### 기본 사용

```bash
# 크롤러 결과로 퍼징 실행
python main.py ../crawler/dynamic_crawl_results.json

# 결과를 특정 파일에 저장
python main.py ../crawler/dynamic_crawl_results.json -o my_results.json

# 최소 위험도 설정 (기본: 30)
python main.py ../crawler/dynamic_crawl_results.json -r 50

# 최대 타겟 수 제한 (기본: 10)
python main.py ../crawler/dynamic_crawl_results.json -m 5
```

### OOB 도메인 설정

```bash
# 커스텀 OOB 도메인 사용
python main.py crawler_results.json -d your-domain.com
```

## 모듈 구조

```
ssrf-modules/
├── input/              # 크롤러 결과 파싱
│   └── json_parser.py  # SSRF 타겟 추출
├── config/             # 설정 및 페이로드
│   └── payloads.py     # SSRF 페이로드 데이터베이스
├── fuzzer/             # 페이로드 생성 엔진
│   └── payload_engine.py # 지능형 페이로드 생성
├── detector/           # 취약점 탐지
│   └── multi_layer_detector.py # 4레이어 탐지 시스템
├── collaborator/       # OOB 서버
│   └── oob_server.py   # DNS/HTTP Collaborator
└── main.py            # 메인 실행 스크립트
```

## 탐지 방법

### 1. 타이밍 기반 탐지
- DNS 지연 패턴 분석
- 포트 스캔 타이밍 측정
- 응답 시간 이상 탐지

### 2. 응답 패턴 분석
- 상태 코드 변화 감지
- 컨텐츠 길이 분석
- 에러 메시지 패턴 매칭

### 3. OOB (Out-of-Band) 탐지
- DNS 쿼리 인터랙션 캡처
- HTTP 요청 로깅
- 블라인드 SSRF 확인

### 4. 컨텍스트 분석
- 엔드포인트 타입 분류
- 파라미터 위험도 평가
- 환경별 가중치 적용

## 페이로드 카테고리

- **기본 내부**: localhost, 127.0.0.1, 192.168.x.x
- **IP 인코딩**: 10진수, 8진수, 16진수 변환
- **DNS 우회**: nip.io, xip.io, sslip.io 활용
- **프로토콜 변조**: gopher, dict, file, ftp, ldap
- **클라우드 메타데이터**: AWS, Azure, GCP 서비스
- **URL 파싱 혼동**: @ 기호, # 프래그먼트, null 바이트
- **유니코드 우회**: 특수 유니코드 문자 활용

## 출력 예시

```
=====================================
SSRF 퍼징 결과 요약
=====================================
총 취약점: 3개
심각 (80%+): 1개
높음 (60-79%): 2개
중간 (40-59%): 0개

취약점 타입별:
  timing_based_ssrf: 1개
  blind_ssrf: 2개

발견된 취약점:
  1. [95.0%] http://target.com/api/fetch
     파라미터: url, 타입: blind_ssrf
  2. [75.0%] http://target.com/proxy
     파라미터: target, 타입: timing_based_ssrf
=====================================
```

## 주의사항

- **권한**: DNS 서버 실행을 위해 관리자 권한 필요
- **방화벽**: OOB 포트(53, 80) 개방 필요
- **도메인**: 실제 OOB 테스트를 위해서는 외부 접근 가능한 도메인 필요
- **법적 책임**: 허가된 대상에 대해서만 테스트 수행

## 라이선스

연구 및 교육 목적으로만 사용
