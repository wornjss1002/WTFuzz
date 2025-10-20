# XSS Fuzzer 모듈 - 개발 문서

## 프로젝트 개요

### 역할
**크롤러 → XSS Fuzzer → 익스플로잇** 파이프라인의 중간 단계

- **입력**: 크롤러가 발견한 엔드포인트 (JSON)
- **처리**: XSS 페이로드로 퍼징 및 탐지
- **출력**: 취약점 발견 결과 (JSON) → 익스플로잇 모듈로 전달

### 기술 스택
- **언어**: Python 3.9+
- **브라우저 자동화**: Playwright
- **데이터 구조**: Dataclass (공통 모듈 사용)
- **출력**: JSON

---

## 아키텍처 설계

### 전체 파이프라인
```
┌──────────┐      ┌──────────┐      ┌──────────┐
│ Crawler  │ JSON │   XSS    │ JSON │ Exploit  │
│  Module  │─────>│  Fuzzer  │─────>│  Module  │
└──────────┘      └──────────┘      └──────────┘
                       │
                       ├─ Payload Generator
                       ├─ Detection Engine
                       └─ Input Handler
```

### XSS Fuzzer 내부 구조
```
xss_fuzzer.py (메인)
    │
    ├─> InputHandler
    │   └─ 크롤러 JSON 로드
    │   └─ 엔드포인트 검증
    │   └─ 테스트 URL 생성
    │
    ├─> PayloadGenerator
    │   └─ 58개 페이로드 (4개 카테고리)
    │   └─ 레벨별 페이로드 (1-4)
    │
    └─> DetectionEngine
        └─ Playwright 브라우저 자동화
        └─ 6가지 탐지 메커니즘
        └─ 신뢰도 계산
```

---

## 공통 모델 (WTFuzz/common/models.py)

### 데이터 구조
```python
# 크롤러 → XSS
@dataclass
class Endpoint:
    url, method, parameters, headers, cookies

@dataclass
class Parameter:
    name, param_type, value, required

# XSS 내부
@dataclass
class Payload:
    id, payload, category, context, severity

# XSS → 익스플로잇
@dataclass
class XSSTestResult:
    endpoint, parameter, payload, vulnerable, confidence

@dataclass
class ExploitTarget:
    vuln_type, endpoint, parameter, successful_payload
```

---

## 모듈 구조

### 1. Input Handler
**파일**: `src/modules/input_handler.py`

**역할**:
- 크롤러 JSON 파일 로드
- Endpoint 객체로 변환
- 테스트 가능한 파라미터 필터링 (query, body만)
- 페이로드 삽입 URL 생성

**주요 메서드**:
```python
InputHandler.from_json_file(file_path) -> List[Endpoint]
InputHandler.build_test_url(endpoint, param_name, payload) -> str
InputHandler.get_testable_parameters(endpoint) -> List[Parameter]
```

### 2. Payload Generator
**파일**: `src/modules/payload_generator.py`

**페이로드 카테고리** (58개):
1. **Basic (10개)**: `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`
2. **Bypass (15개)**: 대소문자 혼합, 인코딩 우회
3. **Context-Aware (18개)**: 태그 탈출, 속성 주입
4. **Encoding (15개)**: URL, HTML 엔티티, Base64

**레벨 전략**:
```
Level 1: Basic only (빠른 테스트)
Level 2: Basic + Bypass
Level 3: Basic + Bypass + Context-Aware
Level 4: 전체 (가장 철저)
```

### 3. Detection Engine
**파일**: `src/modules/detection_engine.py`

**6가지 탐지 메커니즘**:
1. **Console Detection**: 브라우저 콘솔 메시지 모니터링
2. **Dialog Detection**: alert/confirm/prompt 캡처
3. **DOM Mutation Detection**: DOM 변화 추적
4. **Execution Context Detection**: JavaScript 실행 확인
5. **CSP Violation Detection**: CSP 위반 감지
6. **Network Activity Detection**: 외부 요청 모니터링

**신뢰도 계산**:
- HIGH: 3개 이상 메서드 트리거
- MEDIUM: 2개 메서드 트리거
- LOW: 1개 메서드 트리거

### 4. XSS Fuzzer (메인)
**파일**: `xss_fuzzer.py`

**실행 흐름**:
```python
1. 크롤러 JSON 로드
2. 각 엔드포인트에 대해:
   - 테스트 가능한 파라미터 추출
   - 각 파라미터에 페이로드 삽입
   - Detection Engine으로 탐지
   - 결과 수집
3. JSON 출력 (2가지):
   - xss_results.json (상세 결과)
   - exploit_input.json (익스플로잇 모듈용)
```

---

## 사용 방법

### 기본 실행
```bash
python xss_fuzzer.py -i crawler_output.json -o results.json
```

### 옵션
```bash
-i, --input           # 크롤러 출력 JSON (필수)
-o, --output          # 결과 JSON (기본: xss_results.json)
-e, --exploit-output  # 익스플로잇 입력 JSON (기본: exploit_input.json)
-l, --level           # 페이로드 레벨 1-4 (기본: 1)
--max-payloads        # 파라미터당 최대 페이로드 수 (기본: 10)
--headless            # 헤드리스 모드
```

### 예제
```bash
# Level 2로 퍼징 (Bypass 포함)
python xss_fuzzer.py -i endpoints.json -l 2 --headless

# 파라미터당 5개 페이로드만 테스트
python xss_fuzzer.py -i endpoints.json --max-payloads 5
```

---

## 입출력 형식

### 입력 (크롤러 출력)
```json
[
  {
    "url": "https://example.com/search?q=test",
    "method": "GET",
    "parameters": [
      {
        "name": "q",
        "type": "query",
        "value": "test",
        "required": false
      }
    ],
    "headers": {},
    "cookies": {},
    "discovered_by": "crawler"
  }
]
```

### 출력 1: XSS 결과
```json
{
  "total_endpoints": 10,
  "vulnerable_count": 3,
  "vulnerable_endpoints": [
    {
      "endpoint": "https://example.com/search",
      "parameter": "q",
      "payload": "<script>alert(1)</script>",
      "vulnerable": true,
      "confidence": "HIGH",
      "detection_methods": ["dialog", "console"]
    }
  ]
}
```

### 출력 2: 익스플로잇 입력
```json
[
  {
    "vuln_type": "xss",
    "endpoint": "https://example.com/search",
    "parameter": "q",
    "successful_payload": "<script>alert(1)</script>",
    "confidence": "HIGH"
  }
]
```

---

## 파일 구조

```
WTFuzz/
├── common/
│   ├── __init__.py
│   └── models.py                 # 공통 dataclass
│
├── XSS/
│   ├── xss_fuzzer.py            # 메인 실행 파일 ⭐
│   ├── requirements.txt
│   ├── claude.md                # 이 파일
│   ├── src/
│   │   └── modules/
│   │       ├── input_handler.py
│   │       ├── payload_generator.py
│   │       └── detection_engine.py
│   └── payloads/
│       ├── basic.json
│       ├── bypass.json
│       ├── context_aware.json
│       └── encoding.json
```

---

## 개발 노트

### 완료된 작업
- [x] 공통 models.py 생성 (팀 공유)
- [x] Payload Generator (58개 페이로드)
- [x] Input Handler (크롤러 데이터 처리)
- [x] Detection Engine (Playwright 기반)
- [x] XSS Fuzzer 메인 모듈
- [x] JSON 출력 (익스플로잇 모듈 호환)

### 설계 결정
- **리포트 제거**: 익스플로잇 모듈에 JSON만 전달
- **공통 모델**: WTFuzz/common/models.py에서 dataclass 공유
- **간소화**: 필요한 기능만 구현 (빠른 퍼징)
- **모듈 독립성**: 크롤러/익스플로잇과 JSON으로만 통신

### 다음 단계
- [ ] 실제 크롤러 출력으로 통합 테스트
- [ ] 익스플로잇 모듈과 연동 테스트
- [ ] 성능 최적화 (병렬 처리)
- [ ] PortSwigger Labs 검증

---

## 팀 협업 가이드

### 공통 모델 사용
```python
# 다른 모듈에서 import
from common.models import Endpoint, Parameter, XSSTestResult

# Endpoint 객체 생성
endpoint = Endpoint(
    url="https://example.com",
    method=HTTPMethod.GET,
    parameters=[...]
)
```

### 크롤러 팀
- **출력**: `Endpoint` 리스트를 JSON으로 저장
- **형식**: `endpoint.to_dict()` 사용

### 익스플로잇 팀
- **입력**: `ExploitTarget` 리스트를 JSON에서 로드
- **형식**: `exploit_input.json` 파일 읽기

---

*최종 업데이트: 2025-10-20*
