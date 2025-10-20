"""
WTFuzz 공통 데이터 모델
====================

모든 모듈(Crawler, XSS, SSRF, Exploit 등)에서 공유하는 표준 데이터 구조
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum


# ==================== Enums ====================

class HTTPMethod(Enum):
    """HTTP 메서드"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class ParameterType(Enum):
    """파라미터 타입"""
    QUERY = "query"
    BODY = "body"
    HEADER = "header"
    COOKIE = "cookie"
    PATH = "path"


class VulnerabilityType(Enum):
    """취약점 타입"""
    XSS = "xss"
    SSRF = "ssrf"
    SQLI = "sqli"
    IDOR = "idor"
    LFI = "lfi"
    RCE = "rce"
    UNKNOWN = "unknown"


class ConfidenceLevel(Enum):
    """탐지 신뢰도"""
    HIGH = "HIGH"        # 90-100%
    MEDIUM = "MEDIUM"    # 60-89%
    LOW = "LOW"          # 30-59%
    FALSE = "FALSE"      # 0-29%


# ==================== 크롤러 → XSS 입력 데이터 ====================

@dataclass
class Parameter:
    """
    HTTP 파라미터 정보
    크롤러가 발견한 파라미터를 XSS/SSRF 모듈에 전달
    """
    name: str
    param_type: ParameterType
    value: Optional[str] = None
    required: bool = False

    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'type': self.param_type.value,
            'value': self.value,
            'required': self.required
        }


@dataclass
class Endpoint:
    """
    크롤러가 발견한 엔드포인트
    XSS/SSRF 모듈의 입력 데이터
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


# ==================== XSS 페이로드 ====================

@dataclass
class Payload:
    """
    XSS 페이로드 정보
    """
    id: str
    payload: str
    category: str  # basic, bypass, context_aware, encoding
    context: List[str]  # html, script, attribute, etc.
    severity: str  # high, medium, low

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'payload': self.payload,
            'category': self.category,
            'context': self.context,
            'severity': self.severity
        }


# ==================== XSS 탐지 결과 ====================

@dataclass
class DetectionEvidence:
    """
    XSS 탐지 증거
    """
    method: str  # console, dialog, dom_mutation, etc.
    triggered: bool
    data: Any = None

    def to_dict(self) -> Dict:
        return {
            'method': self.method,
            'triggered': self.triggered,
            'data': str(self.data) if self.data else None
        }


@dataclass
class XSSTestResult:
    """
    XSS 퍼징 결과 (단일 테스트)
    XSS 모듈 → 익스플로잇 모듈 전달 데이터
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
    XSS 모듈의 최종 출력
    """
    total_endpoints: int
    total_tests: int
    vulnerable_endpoints: List[XSSTestResult] = field(default_factory=list)
    safe_endpoints: List[str] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None

    def to_dict(self) -> Dict:
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


# ==================== 익스플로잇 입력 데이터 ====================

@dataclass
class ExploitTarget:
    """
    익스플로잇 모듈 입력 데이터
    XSS/SSRF 등에서 취약점 발견 시 전달
    """
    vuln_type: VulnerabilityType
    endpoint: str
    parameter: str
    successful_payload: str
    confidence: ConfidenceLevel
    additional_info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
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
    """딕셔너리를 Endpoint 객체로 변환"""
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
    """딕셔너리를 Payload 객체로 변환"""
    return Payload(
        id=data['id'],
        payload=data['payload'],
        category=data['category'],
        context=data['context'],
        severity=data['severity']
    )
