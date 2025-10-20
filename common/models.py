"""
WTFuzz 공통 데이터 모델
====================

모든 모듈(Crawler, XSS, Exploit)에서 공유하는 표준 데이터 구조

팀 협업을 위한 공통 인터페이스:
- 크롤러 팀: Endpoint 생성 → JSON 저장
- XSS 팀: Endpoint 로드 → 퍼징 → XSSTestResult/ExploitTarget 생성
- 익스플로잇 팀: ExploitTarget 로드 → 익스플로잇 수행
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum


# ==================== Enums (열거형) ====================

class HTTPMethod(Enum):
    """
    HTTP 메서드 정의

    사용처: 모든 모듈 (Endpoint 객체에서 사용)
    용도: HTTP 요청 메서드 표준화

    예시:
        method = HTTPMethod.GET
        method = HTTPMethod.POST
    """
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class ParameterType(Enum):
    """
    HTTP 파라미터 타입 정의

    사용처: 모든 모듈 (Parameter 객체에서 사용)
    용도: 파라미터가 어디에 위치하는지 구분

    타입별 의미:
    - QUERY: URL 쿼리 스트링 (?key=value)
    - BODY: HTTP 바디 (POST 데이터)
    - HEADER: HTTP 헤더
    - COOKIE: 쿠키
    - PATH: URL 경로 파라미터 (/user/{id})

    예시:
        param_type = ParameterType.QUERY
        param_type = ParameterType.BODY
    """
    QUERY = "query"
    BODY = "body"
    HEADER = "header"
    COOKIE = "cookie"
    PATH = "path"


class VulnerabilityType(Enum):
    """
    취약점 타입 정의

    사용처: ExploitTarget 객체
    용도: 발견된 취약점의 종류 분류

    타입별 의미:
    - XSS: Cross-Site Scripting
    - UNKNOWN: 미분류

    예시:
        vuln_type = VulnerabilityType.XSS
    """
    XSS = "xss"
    UNKNOWN = "unknown"


class ConfidenceLevel(Enum):
    """
    탐지 신뢰도 레벨

    사용처: XSSTestResult, ExploitTarget
    용도: 취약점 탐지 결과의 신뢰도 표시

    레벨별 의미:
    - HIGH (90-100%): 3개 이상 탐지 메서드 트리거, 매우 확실
    - MEDIUM (60-89%): 2개 탐지 메서드 트리거, 취약점 가능성 높음
    - LOW (30-59%): 1개 탐지 메서드 트리거, 추가 검증 필요
    - FALSE (0-29%): 탐지 실패, 취약점 없음

    예시:
        confidence = ConfidenceLevel.HIGH
    """
    HIGH = "HIGH"        # 90-100%
    MEDIUM = "MEDIUM"    # 60-89%
    LOW = "LOW"          # 30-59%
    FALSE = "FALSE"      # 0-29%


# ==================== 크롤러 → XSS 퍼저 ====================

@dataclass
class Parameter:
    """
    HTTP 파라미터 정보

    사용처: Endpoint 객체의 parameters 리스트
    생성자: 크롤러 모듈
    사용자: XSS 퍼저 모듈

    필드 설명:
    - name: 파라미터 이름 (예: "q", "search", "id")
    - param_type: 파라미터 위치 (QUERY, BODY, HEADER, COOKIE, PATH)
    - value: 기본값 또는 예시 값 (선택사항)
    - required: 필수 파라미터 여부

    사용 예시:
        # 크롤러가 발견한 파라미터 생성
        param = Parameter(
            name="search",
            param_type=ParameterType.QUERY,
            value="test",
            required=False
        )

        # XSS 모듈에서 사용
        if param.param_type == ParameterType.QUERY:
            # 쿼리 파라미터에 페이로드 삽입
            test_url = f"{url}?{param.name}={xss_payload}"
    """
    name: str
    param_type: ParameterType
    value: Optional[str] = None
    required: bool = False

    def to_dict(self) -> Dict:
        """JSON 직렬화용"""
        return {
            'name': self.name,
            'type': self.param_type.value,
            'value': self.value,
            'required': self.required
        }


@dataclass
class Endpoint:
    """
    크롤러가 발견한 엔드포인트 정보

    사용처: 크롤러 → XSS 퍼저 모듈 전달
    생성자: 크롤러 모듈
    사용자: XSS 퍼저 모듈

    필드 설명:
    - url: 엔드포인트 URL (예: "https://example.com/search?q=test")
    - method: HTTP 메서드 (GET, POST, etc.)
    - parameters: 테스트 가능한 파라미터 리스트
    - headers: 필요한 HTTP 헤더 (선택사항)
    - cookies: 필요한 쿠키 (선택사항)
    - auth_token: 인증 토큰 (선택사항)
    - discovered_by: 발견한 모듈 ("crawler", "manual" 등)
    - timestamp: 발견 시각

    사용 예시:
        # 크롤러 - Endpoint 생성 및 JSON 저장
        endpoint = Endpoint(
            url="https://example.com/search?q=test",
            method=HTTPMethod.GET,
            parameters=[
                Parameter(name="q", param_type=ParameterType.QUERY)
            ],
            headers={"User-Agent": "Mozilla/5.0"},
            cookies={"session": "abc123"}
        )

        # JSON으로 저장
        with open('crawler_output.json', 'w') as f:
            json.dump([endpoint.to_dict()], f)

        # XSS 모듈 - JSON에서 로드
        endpoints = InputHandler.from_json_file('crawler_output.json')
        for ep in endpoints:
            print(ep.url, ep.parameters)
    """
    url: str
    method: HTTPMethod
    parameters: List[Parameter] = field(default_factory=list)
    headers: Optional[Dict[str, str]] = None
    cookies: Optional[Dict[str, str]] = None
    auth_token: Optional[str] = None
    discovered_by: str = "crawler"
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict:
        """JSON 직렬화용"""
        return {
            'url': self.url,
            'method': self.method.value,
            'parameters': [p.to_dict() for p in self.parameters],
            'headers': self.headers,
            'cookies': self.cookies,
            'auth_token': self.auth_token,
            'discovered_by': self.discovered_by,
            'timestamp': self.timestamp.isoformat()
        }


# ==================== XSS 모듈 내부 ====================

@dataclass
class Payload:
    """
    XSS 페이로드 정보

    사용처: XSS 모듈 내부 (PayloadGenerator)
    생성자: PayloadGenerator (JSON 파일에서 로드)
    사용자: XSS Fuzzer

    필드 설명:
    - id: 페이로드 고유 ID (예: "basic_001", "bypass_015")
    - payload: 실제 XSS 페이로드 문자열 (예: "<script>alert(1)</script>")
    - category: 카테고리 (basic, bypass, context_aware, encoding)
    - context: 적용 가능한 컨텍스트 리스트 (html, script, attribute 등)
    - severity: 심각도 (high, medium, low)

    사용 예시:
        # PayloadGenerator에서 로드
        payload = Payload(
            id="basic_001",
            payload="<script>alert(1)</script>",
            category="basic",
            context=["html"],
            severity="high"
        )

        # Fuzzer에서 사용
        test_url = f"{endpoint.url}?param={payload.payload}"
    """
    id: str
    payload: str
    category: str  # basic, bypass, context_aware, encoding
    context: List[str]  # html, script, attribute, etc.
    severity: str  # high, medium, low

    def to_dict(self) -> Dict:
        """JSON 직렬화용"""
        return {
            'id': self.id,
            'payload': self.payload,
            'category': self.category,
            'context': self.context,
            'severity': self.severity
        }


@dataclass
class DetectionEvidence:
    """
    XSS 탐지 증거

    사용처: XSSTestResult의 evidence 리스트
    생성자: DetectionEngine (탐지 메서드별로 생성)
    사용자: XSS Fuzzer (결과 수집)

    필드 설명:
    - method: 탐지 메서드 이름 (console, dialog, dom_mutation 등)
    - triggered: 탐지 여부 (True/False)
    - data: 탐지된 추가 정보 (선택사항)

    사용 예시:
        # DetectionEngine에서 생성
        evidence = DetectionEvidence(
            method="dialog",
            triggered=True,
            data={'type': 'alert', 'message': '1'}
        )

        # Fuzzer에서 수집
        if evidence.triggered:
            print(f"탐지 메서드: {evidence.method}")
    """
    method: str  # console, dialog, dom_mutation, execution_context, csp_violation, network_activity
    triggered: bool
    data: Any = None

    def to_dict(self) -> Dict:
        """JSON 직렬화용"""
        return {
            'method': self.method,
            'triggered': self.triggered,
            'data': str(self.data) if self.data else None
        }


# ==================== 퍼저 → 익스플로잇 ====================

@dataclass
class XSSTestResult:
    """
    XSS 퍼징 단일 테스트 결과

    사용처: XSS Fuzzer → 익스플로잇 모듈
    생성자: XSS Fuzzer (각 테스트마다 생성)
    사용자: 익스플로잇 모듈, 리포트 생성

    필드 설명:
    - endpoint: 테스트한 엔드포인트 URL
    - parameter: 테스트한 파라미터 이름
    - payload: 성공한 XSS 페이로드
    - vulnerable: 취약점 여부 (True/False)
    - confidence: 탐지 신뢰도 (HIGH, MEDIUM, LOW)
    - detection_methods: 트리거된 탐지 메서드 리스트
    - evidence: 탐지 증거 리스트
    - execution_time: 테스트 소요 시간 (초)
    - timestamp: 테스트 시각

    사용 예시:
        # XSS Fuzzer에서 생성
        result = XSSTestResult(
            endpoint="https://example.com/search",
            parameter="q",
            payload="<script>alert(1)</script>",
            vulnerable=True,
            confidence=ConfidenceLevel.HIGH,
            detection_methods=["dialog", "console"],
            execution_time=2.5
        )

        # 익스플로잇 모듈로 전달
        if result.vulnerable and result.confidence == ConfidenceLevel.HIGH:
            # 익스플로잇 수행
            exploit_target = ExploitTarget.from_xss_result(result)
    """
    endpoint: str
    parameter: str
    payload: str
    vulnerable: bool
    confidence: ConfidenceLevel
    detection_methods: List[str] = field(default_factory=list)
    evidence: List[DetectionEvidence] = field(default_factory=list)
    execution_time: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict:
        """JSON 직렬화용"""
        return {
            'endpoint': self.endpoint,
            'parameter': self.parameter,
            'payload': self.payload,
            'vulnerable': self.vulnerable,
            'confidence': self.confidence.value,
            'detection_methods': self.detection_methods,
            'evidence': [e.to_dict() for e in self.evidence],
            'execution_time': self.execution_time,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class XSSFuzzingResult:
    """
    XSS 퍼징 전체 결과 (여러 엔드포인트)

    사용처: XSS Fuzzer 최종 결과
    생성자: XSS Fuzzer (전체 퍼징 완료 시)
    사용자: 리포트 생성, 통계 분석

    필드 설명:
    - total_endpoints: 테스트한 총 엔드포인트 수
    - total_tests: 수행한 총 테스트 수
    - vulnerable_endpoints: 취약한 엔드포인트 결과 리스트
    - safe_endpoints: 안전한 엔드포인트 URL 리스트
    - start_time: 퍼징 시작 시각
    - end_time: 퍼징 종료 시각

    사용 예시:
        # XSS Fuzzer에서 생성
        fuzzing_result = XSSFuzzingResult(
            total_endpoints=10,
            total_tests=50,
            vulnerable_endpoints=[...],  # XSSTestResult 리스트
            safe_endpoints=["https://safe1.com", "https://safe2.com"],
            start_time=datetime.now(),
            end_time=datetime.now()
        )

        # JSON 저장
        with open('xss_results.json', 'w') as f:
            json.dump(fuzzing_result.to_dict(), f, indent=2)
    """
    total_endpoints: int
    total_tests: int
    vulnerable_endpoints: List[XSSTestResult] = field(default_factory=list)
    safe_endpoints: List[str] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None

    def to_dict(self) -> Dict:
        """JSON 직렬화용"""
        return {
            'total_endpoints': self.total_endpoints,
            'total_tests': self.total_tests,
            'vulnerable_count': len(self.vulnerable_endpoints),
            'safe_count': len(self.safe_endpoints),
            'vulnerable_endpoints': [v.to_dict() for v in self.vulnerable_endpoints],
            'safe_endpoints': self.safe_endpoints,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None
        }


@dataclass
class ExploitTarget:
    """
    익스플로잇 모듈 입력 데이터

    사용처: 퍼저 → 익스플로잇 모듈
    생성자: XSS 퍼저 (취약점 발견 시)
    사용자: 익스플로잇 모듈

    필드 설명:
    - vuln_type: 취약점 타입 (XSS)
    - endpoint: 취약한 엔드포인트 URL
    - parameter: 취약한 파라미터 이름
    - successful_payload: 성공한 페이로드
    - confidence: 신뢰도 레벨
    - additional_info: 추가 정보 (선택사항)

    사용 예시:
        # XSS Fuzzer에서 생성
        exploit_target = ExploitTarget(
            vuln_type=VulnerabilityType.XSS,
            endpoint="https://example.com/search",
            parameter="q",
            successful_payload="<script>alert(1)</script>",
            confidence=ConfidenceLevel.HIGH,
            additional_info={
                'detection_methods': ['dialog', 'console'],
                'execution_time': 2.5
            }
        )

        # JSON 저장 (익스플로잇 모듈 입력)
        with open('exploit_input.json', 'w') as f:
            json.dump([exploit_target.to_dict()], f, indent=2)

        # 익스플로잇 모듈에서 로드
        with open('exploit_input.json') as f:
            targets = json.load(f)
            for target in targets:
                if target['vuln_type'] == 'xss':
                    perform_xss_exploit(target)
    """
    vuln_type: VulnerabilityType
    endpoint: str
    parameter: str
    successful_payload: str
    confidence: ConfidenceLevel
    additional_info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """JSON 직렬화용"""
        return {
            'vuln_type': self.vuln_type.value,
            'endpoint': self.endpoint,
            'parameter': self.parameter,
            'successful_payload': self.successful_payload,
            'confidence': self.confidence.value,
            'additional_info': self.additional_info
        }


# ==================== 헬퍼 함수 ====================

def endpoint_from_dict(data: Dict) -> Endpoint:
    """
    딕셔너리를 Endpoint 객체로 변환

    용도: JSON 파일에서 Endpoint 로드

    예시:
        with open('crawler_output.json') as f:
            data = json.load(f)
            endpoints = [endpoint_from_dict(d) for d in data]
    """
    return Endpoint(
        url=data['url'],
        method=HTTPMethod(data['method']),
        parameters=[
            Parameter(
                name=p['name'],
                param_type=ParameterType(p['type']),
                value=p.get('value'),
                required=p.get('required', False)
            )
            for p in data.get('parameters', [])
        ],
        headers=data.get('headers'),
        cookies=data.get('cookies'),
        discovered_by=data.get('discovered_by', 'crawler')
    )


def payload_from_dict(data: Dict) -> Payload:
    """
    딕셔너리를 Payload 객체로 변환

    용도: JSON 파일에서 Payload 로드

    예시:
        with open('payloads/basic.json') as f:
            data = json.load(f)
            payloads = [payload_from_dict(p) for p in data['payloads']]
    """
    return Payload(
        id=data['id'],
        payload=data['payload'],
        category=data['category'],
        context=data['context'],
        severity=data['severity']
    )
