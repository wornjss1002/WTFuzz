"""
XSS Fuzzer Crawler - Dataclass 기반 동적 웹 크롤러
XSS 취약점 테스트를 위한 인젝션 포인트 자동 수집

주요 기능:
1. 폼 입력 필드 수집
2. URL 파라미터 추출
3. API 엔드포인트 탐지
4. XSS 인젝션 포인트 식별
5. CSP 및 보안 설정 분석
6. 무한 스크롤 및 동적 콘텐츠 처리
7. 폼 자동 제출
8. 인터랙티브 요소 자동 클릭
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlsplit
from datetime import datetime
from playwright.sync_api import sync_playwright, Page, Browser, BrowserContext
import json
import time
import re


# ========================================
# 정규식 패턴 (민감정보 탐지용)
# ========================================

# 이메일 패턴
EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

# 전화번호 패턴 (한국)
PHONE_PATTERNS = [
    r'\d{3}-\d{4}-\d{4}',           # 010-1234-5678
    r'\d{2,3}-\d{3,4}-\d{4}',       # 02-123-4567
    r'\(\d{2,3}\)\s?\d{3,4}-\d{4}'  # (02) 123-4567
]

# 신용카드 패턴
CREDIT_CARD_PATTERN = r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'

# 주민번호 패턴 (한국)
SSN_PATTERN = r'\d{6}[-\s]?\d{7}'

# API 키 패턴
API_KEY_PATTERNS = [
    r'sk_live_[A-Za-z0-9]{24,}',    # Stripe
    r'sk_test_[A-Za-z0-9]{24,}',    # Stripe Test
    r'AKIA[0-9A-Z]{16}',            # AWS Access Key
    r'ghp_[A-Za-z0-9]{36}',         # GitHub Personal Token
    r'gho_[A-Za-z0-9]{36}',         # GitHub OAuth Token
    r'AIza[0-9A-Za-z\-_]{35}',      # Google API Key
    r'ya29\.[0-9A-Za-z\-_]+',       # Google OAuth Token
]

# JWT 토큰 패턴
JWT_PATTERN = r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/]+'

# 내부 IP 패턴
INTERNAL_IP_PATTERNS = [
    r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',           # 10.x.x.x
    r'\b172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}\b',  # 172.16.x.x - 172.31.x.x
    r'\b192\.168\.\d{1,3}\.\d{1,3}\b'               # 192.168.x.x
]


# ========================================
# 유틸리티 함수
# ========================================

def safe_text(text: str) -> str:
    """이모지 및 비ASCII 문자 제거 (Windows 콘솔 출력용)"""
    return text.encode('ascii', 'ignore').decode('ascii')


def normalize_url(url: str) -> str:
    """
    URL 정규화 - 중복 크롤링 방지

    제거 항목:
    - Fragment(#section) - 같은 페이지의 다른 위치
    - 빈 쿼리 파라미터
    - 중복 슬래시

    Args:
        url: 정규화할 URL

    Returns:
        str: 정규화된 URL
    """
    parsed = urlparse(url)

    # Fragment 제거 (# 이하 부분)
    # http://example.com/page#section → http://example.com/page
    normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    # 쿼리 파라미터가 있으면 추가 (정렬하여 일관성 유지)
    if parsed.query:
        # 파라미터 정렬 (중복 파라미터 제거)
        params = parse_qs(parsed.query)
        sorted_params = sorted(params.items())
        query_string = '&'.join(f"{k}={v[0]}" for k, v in sorted_params if v)
        if query_string:
            normalized += f"?{query_string}"

    # 끝의 슬래시 정규화 (선택적)
    # /page와 /page/를 동일하게 취급하려면 주석 해제
    # if normalized.endswith('/') and normalized.count('/') > 3:
    #     normalized = normalized.rstrip('/')

    return normalized


def is_dangerous_url(url: str) -> bool:
    """
    위험한 URL/액션 판별 (로그아웃, CAPTCHA, 삭제 등)

    Args:
        url: 검사할 URL 또는 액션 문자열

    Returns:
        bool: 위험한 URL이면 True
    """
    dangerous_keywords = [
        'logout', 'captcha', 'delete', 'remove', 'reset', 'drop',
        'clear', 'destroy', 'terminate', 'cancel', 'exit'
    ]
    url_lower = url.lower()
    return any(keyword in url_lower for keyword in dangerous_keywords)


def infer_parameter_value(param_name: str, param_type: str, current_value: Optional[str] = None) -> str:
    """
    파라미터 이름과 타입을 기반으로 예시 값 자동 추론

    Args:
        param_name: 파라미터 이름
        param_type: input type (text, password, email, number 등)
        current_value: 현재 value 속성 값

    Returns:
        str: 추론된 예시 값
    """
    # 1. 현재 값이 있으면 그대로 사용
    if current_value:
        return current_value

    # 2. 파라미터 이름 기반 추론 (우선순위)
    name_lower = param_name.lower()

    name_patterns = {
        # 사용자 정보
        'username': 'admin', 'user': 'admin', 'userid': 'admin',
        'login': 'admin', 'account': 'admin',
        'email': 'user@example.com', 'mail': 'user@example.com',

        # 비밀번호
        'password': 'password123', 'passwd': 'password123',
        'pwd': 'password123', 'pass': 'password123',

        # 네트워크 관련
        'ip': '127.0.0.1', 'ipaddress': '192.168.1.1',
        'host': 'localhost', 'domain': 'example.com',
        'url': 'http://example.com', 'port': '8080',

        # 파일 관련
        'file': 'test.txt', 'filename': 'example.txt',
        'path': '/var/www/html', 'upload': 'file.jpg',

        # ID 관련
        'id': '1', 'idx': '1', 'num': '1', 'number': '123',

        # 텍스트 관련
        'name': 'John Doe', 'firstname': 'John', 'lastname': 'Doe',
        'title': 'Test Title', 'comment': 'This is a test comment',
        'message': 'Hello World', 'content': 'Test content',
        'description': 'Test description', 'text': 'sample text',

        # 검색 관련
        'search': 'test', 'query': 'test', 'keyword': 'test', 'q': 'test',

        # 날짜/시간
        'date': '2025-01-01', 'time': '12:00',
        'datetime': '2025-01-01 12:00:00',
        'year': '2025', 'month': '01', 'day': '01',

        # 코드/명령
        'cmd': 'ls', 'command': 'ls -la',
        'code': 'print("hello")', 'sql': 'SELECT * FROM users',

        # 기타
        'phone': '010-1234-5678', 'mobile': '010-1234-5678',
        'zip': '12345', 'zipcode': '12345',
        'address': '123 Main St', 'country': 'Korea', 'city': 'Seoul',
        'token': 'abc123def456', 'key': 'secretkey123', 'value': 'test_value',
    }

    # 패턴 매칭
    for pattern, example_val in name_patterns.items():
        if pattern in name_lower:
            return example_val

    # 3. input type 기반 추론
    type_patterns = {
        'email': 'user@example.com', 'password': 'password123',
        'tel': '010-1234-5678', 'url': 'http://example.com',
        'number': '123', 'date': '2025-01-01', 'time': '12:00',
        'datetime-local': '2025-01-01T12:00', 'month': '2025-01',
        'week': '2025-W01', 'color': '#ff0000', 'range': '50',
        'search': 'search query',
    }

    if param_type in type_patterns:
        return type_patterns[param_type]

    # 4. submit/button 기본값
    if param_type in ['submit', 'button']:
        return 'Submit'

    # 5. 기본값
    return f'test_{param_name}' if param_name else 'test_value'


# ========================================
# Dataclass 정의 (데이터 구조)
# ========================================

@dataclass
class CrawlerConfig:
    """크롤러 설정"""
    headless: bool = False                    # 헤드리스 모드 여부
    viewport_width: int = 1920                # 브라우저 가로 크기
    viewport_height: int = 1080               # 브라우저 세로 크기
    timeout: int = 5000                       # 기본 타임아웃 (ms)
    max_depth: int = 3                        # 최대 크롤링 깊이
    max_pages: int = 50                       # 최대 크롤링 페이지 수
    user_agent: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

    # 크롤링 필터
    exclude_extensions: Set[str] = field(default_factory=lambda: {
        '.jpg', '.jpeg', '.png', '.gif', '.pdf', '.zip',
        '.css', '.js', '.woff', '.ttf', '.svg'
    })

    # 로그인 설정
    username: Optional[str] = None
    password: Optional[str] = None
    login_url: Optional[str] = None

    # 동적 콘텐츠 설정
    handle_infinite_scroll: bool = True       # 무한 스크롤 처리 여부
    max_scrolls: int = 5                      # 최대 스크롤 횟수
    handle_load_more: bool = True             # "더보기" 버튼 처리 여부
    max_load_more_clicks: int = 3             # 최대 "더보기" 클릭 횟수

    # 폼 제출 설정 
    submit_forms: bool = False                # 폼 자동 제출 여부
    max_form_submissions: int = 5             # 최대 폼 제출 개수

    # 인터랙티브 요소 설정 
    trigger_elements: bool = False            # 요소 자동 클릭 여부
    max_element_clicks: int = 10              # 최대 요소 클릭 개수


@dataclass
class InputField:
    """HTML 입력 필드 정보"""
    name: str                                 # 필드 이름
    input_type: str                           # 입력 타입
    value: str = ""                           # 현재 값
    required: bool = False                    # 필수 입력 여부
    pattern: str = ""                         # 정규식 패턴
    min_length: int = 0                       # 최소 길이
    max_length: int = 0                       # 최대 길이

    # 추가 속성 (select/radio 전용)
    options: List[str] = field(default_factory=list)  # select/radio 옵션 값들
    selected_value: str = ""                  # select의 선택된 값

    def is_injectable(self) -> bool:
        """XSS 인젝션 가능 여부 판단"""
        if self.input_type == 'password':
            return False
        # 파일 업로드는 별도 처리
        if self.input_type == 'file':
            return False
        return self.input_type in ['text', 'search', 'email', 'url', 'textarea', 'hidden']

    def is_file_upload(self) -> bool:
        """파일 업로드 필드 여부 (NEW!)"""
        return self.input_type == 'file'

    def get_test_value(self) -> str:
        """테스트용 값 자동 생성"""
        if self.is_file_upload():
            return 'test.txt'  # 파일명
        return infer_parameter_value(self.name, self.input_type, self.value)


@dataclass
class FormInfo:
    """HTML 폼 정보"""
    action: str                               # 폼 액션 URL
    method: str                               # HTTP 메서드
    fields: List[InputField]                  # 입력 필드 리스트
    form_id: str = ""                         # 폼 ID
    form_name: str = ""                       # 폼 이름
    enctype: str = ""                         # 인코딩 타입

    def get_injectable_fields(self) -> List[InputField]:
        """인젝션 가능한 필드만 반환"""
        return [f for f in self.fields if f.is_injectable()]

    def get_file_upload_fields(self) -> List[InputField]:
        """파일 업로드 필드만 반환 (NEW!)"""
        return [f for f in self.fields if f.is_file_upload()]

    def has_file_upload(self) -> bool:
        """파일 업로드 필드 포함 여부 (NEW!)"""
        return len(self.get_file_upload_fields()) > 0

    def analyze_hidden_fields(self) -> Dict[str, List[Dict]]:
        """
        Hidden 필드 분석 - CSRF 토큰 등 구분 (NEW!)

        Returns:
            dict: {
                'csrf_tokens': [...],
                'other_hidden': [...]
            }
        """
        analysis = {
            'csrf_tokens': [],
            'other_hidden': []
        }

        for field in self.fields:
            if field.input_type == 'hidden':
                field_info = {
                    'name': field.name,
                    'value': field.value,
                    'length': len(field.value) if field.value else 0
                }

                # CSRF 토큰 판별
                csrf_keywords = ['csrf', 'token', '_token', 'authenticity', 'xsrf', 'anti-forgery']
                if any(keyword in field.name.lower() for keyword in csrf_keywords):
                    field_info['token_type'] = 'csrf'
                    field_info['pattern'] = 'alphanumeric' if field.value.replace('-', '').replace('_', '').isalnum() else 'mixed'
                    analysis['csrf_tokens'].append(field_info)

                # 기타 hidden 필드
                else:
                    field_info['token_type'] = 'other'
                    analysis['other_hidden'].append(field_info)

        return analysis

    def to_dict(self) -> dict:
        """딕셔너리로 변환"""
        return {
            'action': self.action,
            'method': self.method,
            'form_id': self.form_id,
            'form_name': self.form_name,
            'enctype': self.enctype,
            'has_file_upload': self.has_file_upload(),
            'hidden_fields_analysis': self.analyze_hidden_fields(),  # NEW!
            'fields': [
                {
                    'name': f.name,
                    'type': f.input_type,
                    'value': f.value,
                    'required': f.required,
                    'injectable': f.is_injectable(),
                    'is_file_upload': f.is_file_upload(),
                    'test_value': f.get_test_value(),
                    # select/radio 옵션 (필요시만 포함)
                    'options': f.options if f.options else None,
                    'selected_value': f.selected_value if f.selected_value else None
                }
                for f in self.fields
            ]
        }


@dataclass
class ParameterInfo:
    """파라미터 상세 정보 (NEW!)"""
    name: str                                 # 파라미터 이름
    param_type: str                           # 타입 (query, json, form, multipart)
    location: str                             # 위치 (query, body)
    example_value: Any                        # 예시 값
    required: bool = True                     # 필수 여부


@dataclass
class Endpoint:
    """API 엔드포인트 정보"""
    url: str                                  # 엔드포인트 URL
    method: str                               # HTTP 메서드
    request_type: str                         # 요청 타입
    parameters: List[ParameterInfo] = field(default_factory=list)  # 상세 파라미터 (개선!)
    post_data: Optional[str] = None           # 원본 POST 데이터
    headers: Dict[str, str] = field(default_factory=dict)
    response_status: int = 0
    response_type: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        """딕셔너리로 변환"""
        return {
            'url': self.url,
            'method': self.method,
            'request_type': self.request_type,
            'parameters': [
                {
                    'name': p.name,
                    'type': p.param_type,
                    'location': p.location,
                    'example_value': p.example_value,
                    'required': p.required
                }
                for p in self.parameters
            ],
            'post_data': self.post_data,
            'headers': self.headers,
            'response_status': self.response_status,
            'response_type': self.response_type,
            'timestamp': self.timestamp
        }


@dataclass
class SecurityInfo:
    """보안 분석 정보"""
    url: str
    csp: Optional[str] = None
    csp_source: Optional[str] = None
    csp_parsed: Dict[str, List[str]] = field(default_factory=dict)
    csp_issues: List[str] = field(default_factory=list)
    security_headers: Dict[str, str] = field(default_factory=dict)
    cookies: List[Dict[str, Any]] = field(default_factory=list)
    vulnerable_cookies: List[Dict[str, Any]] = field(default_factory=list)
    js_accessible_cookies: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        """딕셔너리로 변환"""
        return {
            'url': self.url,
            'csp': self.csp,
            'csp_source': self.csp_source,
            'csp_parsed': self.csp_parsed,
            'csp_issues': self.csp_issues,
            'security_headers': self.security_headers,
            'cookies': self.cookies,
            'vulnerable_cookies': self.vulnerable_cookies,
            'js_accessible_cookies': self.js_accessible_cookies,
            'timestamp': self.timestamp
        }


@dataclass
class InjectionPoint:
    """XSS 인젝션 포인트"""
    point_type: str                           # 타입: 'form', 'url_param', 'post_param', 'file_upload'
    url: str                                  # 페이지 URL
    parameter_name: str                       # 파라미터/필드 이름
    method: str                               # HTTP 메서드
    context: str = ""                         # 추가 컨텍스트 정보
    test_value: str = ""                      # 테스트용 기본값

    def to_dict(self) -> dict:
        """딕셔너리로 변환"""
        return {
            'type': self.point_type,
            'url': self.url,
            'parameter': self.parameter_name,
            'method': self.method,
            'context': self.context,
            'test_value': self.test_value
        }


@dataclass
class SensitiveDataInfo:
    """민감 정보 정보"""
    data_type: str                            # 데이터 타입: 'email', 'phone', 'ssn', 'credit_card', 'api_key', 'jwt', 'internal_ip', 'storage', 'data_attribute', 'table_data'
    value: str                                # 발견된 값 (일부 마스킹)
    location: str                             # CSS selector 또는 위치
    context: str                              # 주변 HTML 컨텍스트
    page_url: str                             # 발견된 페이지 URL
    confidence: float                         # 신뢰도 (0.0~1.0)

    def to_dict(self) -> dict:
        """딕셔너리로 변환"""
        return {
            'data_type': self.data_type,
            'value': self.value,
            'location': self.location,
            'context': self.context,
            'page_url': self.page_url,
            'confidence': self.confidence
        }


@dataclass
class CrawlResult:
    """크롤링 결과"""
    base_url: str
    crawled_urls: List[str] = field(default_factory=list)
    forms: List[FormInfo] = field(default_factory=list)
    endpoints: List[Endpoint] = field(default_factory=list)
    injection_points: List[InjectionPoint] = field(default_factory=list)
    security_reports: List[SecurityInfo] = field(default_factory=list)
    sensitive_data: List[SensitiveDataInfo] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    end_time: Optional[str] = None

    def add_form(self, form: FormInfo):
        """폼 추가 및 인젝션 포인트 생성"""
        self.forms.append(form)

        # 일반 인젝션 가능 필드
        for field_info in form.get_injectable_fields():
            injection = InjectionPoint(
                point_type='form',
                url=form.action,
                parameter_name=field_info.name,
                method=form.method,
                context=f"form_id={form.form_id}, field_type={field_info.input_type}",
                test_value=field_info.get_test_value()
            )
            self.injection_points.append(injection)

        # 파일 업로드 필드 (NEW!)
        for field_info in form.get_file_upload_fields():
            injection = InjectionPoint(
                point_type='file_upload',
                url=form.action,
                parameter_name=field_info.name,
                method=form.method,
                context=f"form_id={form.form_id}, enctype={form.enctype}",
                test_value='test.txt'
            )
            self.injection_points.append(injection)

    def add_endpoint(self, endpoint: Endpoint):
        """엔드포인트 추가 및 인젝션 포인트 생성 (개선!)"""
        self.endpoints.append(endpoint)

        # 각 파라미터를 개별 인젝션 포인트로 변환
        for param in endpoint.parameters:
            if param.location == 'query':
                # GET 파라미터
                injection = InjectionPoint(
                    point_type='url_param',
                    url=endpoint.url,
                    parameter_name=param.name,
                    method=endpoint.method,
                    context=f"request_type={endpoint.request_type}, param_type={param.param_type}",
                    test_value=str(param.example_value)
                )
                self.injection_points.append(injection)
            elif param.location == 'body':
                # POST 파라미터 (JSON, Form 등)
                injection = InjectionPoint(
                    point_type='post_param',
                    url=endpoint.url,
                    parameter_name=param.name,
                    method=endpoint.method,
                    context=f"param_type={param.param_type}, content_type={endpoint.headers.get('content-type', 'unknown')}",
                    test_value=str(param.example_value)
                )
                self.injection_points.append(injection)

    def add_security_report(self, report: SecurityInfo):
        """보안 분석 리포트 추가"""
        self.security_reports.append(report)

    def add_sensitive_data(self, data: SensitiveDataInfo):
        """민감 정보 추가"""
        self.sensitive_data.append(data)

    def finalize(self):
        """크롤링 완료 처리"""
        self.end_time = datetime.now().isoformat()

    def to_dict(self) -> dict:
        """딕셔너리로 변환"""
        return {
            'base_url': self.base_url,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'statistics': {
                'total_urls': len(self.crawled_urls),
                'total_forms': len(self.forms),
                'total_endpoints': len(self.endpoints),
                'total_injection_points': len(self.injection_points),
                'form_injection_points': sum(1 for ip in self.injection_points if ip.point_type == 'form'),
                'url_param_injection_points': sum(1 for ip in self.injection_points if ip.point_type == 'url_param'),
                'post_param_injection_points': sum(1 for ip in self.injection_points if ip.point_type == 'post_param'),
                'file_upload_injection_points': sum(1 for ip in self.injection_points if ip.point_type == 'file_upload'),
                'pages_with_csp': sum(1 for r in self.security_reports if r.csp),
                'vulnerable_cookies': sum(len(r.vulnerable_cookies) for r in self.security_reports),
                'total_sensitive_data': len(self.sensitive_data),
                'sensitive_data_by_type': {
                    'email': sum(1 for sd in self.sensitive_data if sd.data_type == 'email'),
                    'phone': sum(1 for sd in self.sensitive_data if sd.data_type == 'phone'),
                    'credit_card': sum(1 for sd in self.sensitive_data if sd.data_type == 'credit_card'),
                    'ssn': sum(1 for sd in self.sensitive_data if sd.data_type == 'ssn'),
                    'api_key': sum(1 for sd in self.sensitive_data if sd.data_type == 'api_key'),
                    'jwt': sum(1 for sd in self.sensitive_data if sd.data_type == 'jwt'),
                    'internal_ip': sum(1 for sd in self.sensitive_data if sd.data_type == 'internal_ip'),
                    'storage': sum(1 for sd in self.sensitive_data if sd.data_type == 'storage'),
                    'data_attribute': sum(1 for sd in self.sensitive_data if sd.data_type == 'data_attribute'),
                    'table_data': sum(1 for sd in self.sensitive_data if sd.data_type == 'table_data')
                }
            },
            'crawled_urls': self.crawled_urls,
            'forms': [f.to_dict() for f in self.forms],
            'endpoints': [e.to_dict() for e in self.endpoints],
            'injection_points': [ip.to_dict() for ip in self.injection_points],
            'security_reports': [sr.to_dict() for sr in self.security_reports],
            'sensitive_data': [sd.to_dict() for sd in self.sensitive_data],
            'errors': self.errors
        }

    def save_to_json(self, filepath: str):
        """JSON 파일로 저장"""
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
        print(f"[+] 결과 저장 완료: {filepath}")


# ========================================
# 브라우저 제어 클래스
# ========================================

class BrowserController:
    """
    Playwright 브라우저 제어

    주요 기능:
    - 브라우저 시작/종료
    - 페이지 이동 및 대기
    - 사용자 상호작용 (클릭, 입력, 스크롤, 호버 등)
    - 탭 관리
    """

    def __init__(self, config: CrawlerConfig):
        """
        Args:
            config: 크롤러 설정
        """
        self.config = config
        self.playwright = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None

    def start(self):
        """브라우저 시작"""
        print(f"[+] 브라우저 시작 (headless={self.config.headless})")

        self.playwright = sync_playwright().start()
        self.browser = self.playwright.chromium.launch(headless=self.config.headless)

        self.context = self.browser.new_context(
            viewport={
                'width': self.config.viewport_width,
                'height': self.config.viewport_height
            },
            user_agent=self.config.user_agent
        )

        self.page = self.context.new_page()
        print("[+] 브라우저 준비 완료")

    # ========================================
    # 페이지 이동 및 제어
    # ========================================

    def navigate(self, url: str, wait_until: str = 'networkidle') -> bool:
        """URL로 이동"""
        try:
            print(f"[→] 페이지 이동: {url}")
            self.page.goto(url, wait_until=wait_until, timeout=self.config.timeout * 2)
            return True
        except Exception as e:
            print(f"[!] 페이지 이동 실패: {e}")
            return False

    # ========================================
    # 사용자 상호작용
    # ========================================

    def click(self, selector: str) -> bool:
        """요소 클릭"""
        try:
            self.page.click(selector, timeout=self.config.timeout)
            print(f"[+] 클릭 완료: {selector}")
            return True
        except Exception as e:
            print(f"[!] 클릭 실패: {selector} - {e}")
            return False

    def fill(self, selector: str, text: str) -> bool:
        """입력 필드에 텍스트 입력"""
        try:
            self.page.fill(selector, text, timeout=self.config.timeout)
            print(f"[+] 입력 완료: {selector}")
            return True
        except Exception as e:
            print(f"[!] 입력 실패: {selector} - {e}")
            return False
        
    def type_text(self, selector, text, delay=1000):
        """
        텍스트를 천천히 타이핑 (사람처럼)

        Args:
            selector: 입력 필드의 CSS 선택자
            text: 입력할 텍스트
            delay: 각 문자 사이 지연 시간 (ms)
        """
        try:
            self.page.type(selector, text, delay=delay)
            print(f"[+] 타이핑 완료: {selector} = '{text}'")
            return True
        except Exception as e:
            print(f"[!] 타이핑 실패: {selector} - {e}")
            return False

    # ========================================
    # 종료
    # ========================================

    def close(self):
        """브라우저 종료"""
        if self.page:
            self.page.close()
        if self.context:
            self.context.close()
        if self.browser:
            self.browser.close()
        if self.playwright:
            self.playwright.stop()
        print("[+] 브라우저 종료 완료")


# ========================================
# 네트워크 트래픽 캡처 클래스
# ========================================

class NetworkCapture:
    """
    네트워크 트래픽 캡처 및 API 엔드포인트 추출

    주요 기능:
    - HTTP/AJAX 요청 모니터링
    - API 엔드포인트 자동 추출
    - 파라미터 및 페이로드 수집
    - POST 파라미터 상세 분석 (NEW!)
    - 엔드포인트 중복 체크 (NEW!)
    """

    def __init__(self, page: Page, base_url: str):
        """
        Args:
            page: Playwright Page 객체
            base_url: 기준 URL
        """
        self.page = page
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc
        self.endpoints: List[Endpoint] = []
        self.endpoint_keys: Set[str] = set()  # 중복 체크용 (NEW!)
        self.page_response_headers: Dict[str, str] = {}

        self._setup_listeners()

    def _setup_listeners(self):
        """요청/응답 리스너 등록"""
        self.page.on('request', self._on_request)
        self.page.on('response', self._on_response)
        print("[+] 네트워크 캡처 시작")

    def _on_request(self, request):
        """HTTP 요청 캡처"""
        resource_type = request.resource_type

        # 정적 리소스 제외
        if resource_type in ['image', 'stylesheet', 'font', 'media']:
            return

        # URL 파라미터 파싱
        parsed = urlparse(request.url)

        # 중복 체크 (NEW!)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        endpoint_key = f"{request.method}:{base_url}"

        if endpoint_key in self.endpoint_keys:
            return  # 이미 존재하는 엔드포인트

        self.endpoint_keys.add(endpoint_key)

        # GET 파라미터 추출
        params = parse_qs(parsed.query)
        param_list = []

        for param_name, param_values in params.items():
            param_list.append(ParameterInfo(
                name=param_name,
                param_type='query',
                location='query',
                example_value=param_values[0] if param_values else '',
                required=True
            ))

        # 엔드포인트 정보 생성
        endpoint = Endpoint(
            url=base_url,
            method=request.method,
            request_type=resource_type,
            parameters=param_list,
            post_data=request.post_data,
            headers=dict(request.headers)
        )

        # POST 파라미터 상세 분석 (NEW!)
        if request.method in ['POST', 'PUT', 'PATCH'] and request.post_data:
            self._extract_post_parameters(request, endpoint)

        self.endpoints.append(endpoint)

        # 로그 출력
        if resource_type in ['xhr', 'fetch']:
            print(f"  [AJAX] {request.method} {base_url} ({len(endpoint.parameters)}개 파라미터)")
        else:
            print(f"  [HTTP] {request.method} {base_url}")

    def _extract_post_parameters(self, request, endpoint: Endpoint):
        """
        POST 요청에서 파라미터 상세 추출 (NEW!)

        Args:
            request: Playwright Request 객체
            endpoint: Endpoint 객체
        """
        post_data = request.post_data
        content_type = request.headers.get('content-type', '')

        try:
            # JSON 데이터
            if 'application/json' in content_type:
                post_json = json.loads(post_data)
                if isinstance(post_json, dict):
                    for key, value in post_json.items():
                        endpoint.parameters.append(ParameterInfo(
                            name=key,
                            param_type='json',
                            location='body',
                            example_value=value,
                            required=True
                        ))
                        print(f"    → POST 파라미터 (JSON): {key}")

            # Form 데이터
            elif 'application/x-www-form-urlencoded' in content_type:
                params = parse_qs(post_data)
                for param_name, param_values in params.items():
                    endpoint.parameters.append(ParameterInfo(
                        name=param_name,
                        param_type='form',
                        location='body',
                        example_value=param_values[0] if param_values else '',
                        required=True
                    ))
                    print(f"    → POST 파라미터 (Form): {param_name}")

            # Multipart Form 데이터
            elif 'multipart/form-data' in content_type:
                endpoint.parameters.append(ParameterInfo(
                    name='file_upload',
                    param_type='multipart',
                    location='body',
                    example_value='binary_data',
                    required=True
                ))
                print(f"    → POST 파라미터 (Multipart): file_upload")

        except Exception as e:
            print(f"    [!] POST 파라미터 추출 실패: {e}")

    def _on_response(self, response):
        """HTTP 응답 캡처"""
        request = response.request
        resource_type = request.resource_type

        # 메인 페이지 응답 헤더 저장
        if resource_type == 'document':
            self.page_response_headers = dict(response.headers)

        # 정적 리소스 제외
        if resource_type in ['image', 'stylesheet', 'font', 'media']:
            return

        # 엔드포인트 응답 정보 업데이트
        parsed = urlparse(response.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for endpoint in self.endpoints:
            if endpoint.url == base_url and endpoint.response_status == 0:
                endpoint.response_status = response.status

                content_type = response.headers.get('content-type', '')
                if 'application/json' in content_type:
                    endpoint.response_type = 'json'
                elif 'text/html' in content_type:
                    endpoint.response_type = 'html'
                else:
                    endpoint.response_type = 'text'
                break

    def get_endpoints(self) -> List[Endpoint]:
        """수집된 엔드포인트 반환"""
        return self.endpoints

    def get_page_response_headers(self) -> Dict[str, str]:
        """메인 페이지 응답 헤더 반환"""
        return self.page_response_headers


# ========================================
# DOM 분석 및 폼 추출 클래스
# ========================================

class DOMAnalyzer:
    """
    DOM 분석 및 폼/링크 추출

    주요 기능:
    - JavaScript 실행 후 DOM 분석
    - HTML 폼 및 입력 필드 추출
    - 동적 링크 수집
    - 무한 스크롤 처리
    - "더보기" 버튼 자동 클릭
    - 폼 자동 제출 (NEW!)
    - 인터랙티브 요소 자동 클릭 (NEW!)
    """

    def __init__(self, page: Page, base_url: str, config: CrawlerConfig):
        """
        Args:
            page: Playwright Page 객체
            base_url: 기준 URL
            config: 크롤러 설정
        """
        self.page = page
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc
        self.config = config

    def extract_forms(self) -> List[FormInfo]:
        """페이지의 모든 폼 추출"""
        print("[+] 폼 추출 시작")

        forms_data = self.page.evaluate("""
            () => {
                const forms = [];
                document.querySelectorAll('form').forEach((form, index) => {
                    const fields = [];

                    form.querySelectorAll('input, textarea, select').forEach(input => {
                        const fieldData = {
                            name: input.name || input.id || `field_${fields.length}`,
                            type: input.type || input.tagName.toLowerCase(),
                            value: input.value || '',
                            required: input.required || false,
                            pattern: input.pattern || '',
                            minLength: input.minLength || 0,
                            maxLength: input.maxLength || 0,

                            // select/radio 옵션 전용
                            options: [],
                            selectedValue: ''
                        };

                        // Select 옵션 추출
                        if (input.tagName === 'SELECT') {
                            const options = Array.from(input.options).map(opt => opt.value || opt.text);
                            fieldData.options = options;
                            fieldData.selectedValue = input.value;
                        }

                        // Radio 옵션 추출
                        if (input.type === 'radio') {
                            const radioGroup = form.querySelectorAll(`input[name="${input.name}"]`);
                            fieldData.options = Array.from(radioGroup).map(r => r.value);
                        }

                        fields.push(fieldData);
                    });

                    forms.push({
                        action: form.action || window.location.href,
                        method: form.method.toUpperCase() || 'GET',
                        id: form.id || `form_${index}`,
                        name: form.name || '',
                        enctype: form.enctype || '',
                        fields: fields
                    });
                });

                return forms;
            }
        """)

        forms = []
        for form_data in forms_data:
            fields = [
                InputField(
                    name=f['name'],
                    input_type=f['type'],
                    value=f['value'],
                    required=f['required'],
                    pattern=f['pattern'],
                    min_length=f['minLength'],
                    max_length=f['maxLength'],
                    # select/radio 옵션
                    options=f.get('options', []),
                    selected_value=f.get('selectedValue', '')
                )
                for f in form_data['fields']
            ]

            form = FormInfo(
                action=form_data['action'],
                method=form_data['method'],
                fields=fields,
                form_id=form_data['id'],
                form_name=form_data['name'],
                enctype=form_data['enctype']
            )
            forms.append(form)

            file_upload_mark = " [FILE]" if form.has_file_upload() else ""
            print(f"  [폼] {form.method} {form.action} ({len(form.fields)}개 필드){file_upload_mark}")

        return forms

    def extract_links(self) -> List[str]:
        """페이지의 모든 링크 추출"""
        print("[+] 링크 추출 시작")

        links = self.page.evaluate("""
            () => {
                const links = [];
                document.querySelectorAll('a[href]').forEach(link => {
                    links.push(link.href);
                });
                return links;
            }
        """)

        # 같은 도메인의 링크만 필터링
        filtered_links = []
        for link in links:
            parsed = urlparse(link)
            if parsed.netloc == self.base_domain:
                # 위험한 링크 제외 (로그아웃, CAPTCHA 등)
                if not is_dangerous_url(link):
                    filtered_links.append(link)

        print(f"  [링크] {len(filtered_links)}개 발견")
        return filtered_links

    def get_dom_stats(self) -> dict:
        """DOM 통계 정보 수집"""
        stats = self.page.evaluate("""
            () => {
                return {
                    total_elements: document.querySelectorAll('*').length,
                    links: document.querySelectorAll('a[href]').length,
                    forms: document.querySelectorAll('form').length,
                    inputs: document.querySelectorAll('input').length,
                    buttons: document.querySelectorAll('button').length,
                    iframes: document.querySelectorAll('iframe').length
                };
            }
        """)

        print(f"[통계] 요소: {stats['total_elements']}, 폼: {stats['forms']}, 입력: {stats['inputs']}")
        return stats

    # ========================================
    # 동적 콘텐츠 처리
    # ========================================

    def handle_infinite_scroll(self) -> int:
        """
        무한 스크롤 처리

        Returns:
            int: 스크롤 횟수
        """
        if not self.config.handle_infinite_scroll:
            return 0

        print(f"[+] 무한 스크롤 처리 중 (최대 {self.config.max_scrolls}회)...")

        scroll_count = 0

        for i in range(self.config.max_scrolls):
            current_height = self.page.evaluate("document.body.scrollHeight")

            # 맨 아래로 스크롤
            self.page.evaluate("window.scrollTo(0, document.body.scrollHeight);")
            print(f"  → 스크롤 {i+1}/{self.config.max_scrolls}...")

            # 대기
            self.page.wait_for_timeout(1000)

            # 새 높이 확인
            new_height = self.page.evaluate("document.body.scrollHeight")

            # 더 이상 로드되지 않으면 중단
            if new_height == current_height:
                print(f"  → 더 이상 콘텐츠가 로드되지 않습니다.")
                break

            scroll_count += 1

        print(f"  → 총 {scroll_count}회 스크롤 완료")
        return scroll_count

    def handle_load_more_button(self) -> int:
        """
        "더보기" 버튼 자동 클릭

        Returns:
            int: 클릭 횟수
        """
        if not self.config.handle_load_more:
            return 0

        print("[+] '더보기' 버튼 처리 중...")

        # 일반적인 "더보기" 버튼 선택자
        button_selectors = [
            'button:has-text("더보기")',
            'button:has-text("Load More")',
            'button:has-text("Show More")',
            'a:has-text("더보기")',
            'a:has-text("Load More")',
            '.load-more',
            '.show-more',
            '#load-more'
        ]

        click_count = 0

        for i in range(self.config.max_load_more_clicks):
            clicked = False

            for selector in button_selectors:
                try:
                    # 버튼이 있는지 확인
                    if self.page.locator(selector).count() > 0:
                        # 버튼이 보이도록 스크롤
                        self.page.locator(selector).scroll_into_view_if_needed()
                        # 클릭
                        self.page.click(selector, timeout=2000)
                        print(f"  → '더보기' 버튼 클릭 {i+1}/{self.config.max_load_more_clicks}")
                        clicked = True
                        click_count += 1

                        # 로딩 대기
                        self.page.wait_for_timeout(1000)
                        break
                except:
                    continue

            if not clicked:
                print("  → '더보기' 버튼을 찾을 수 없습니다.")
                break

        if click_count > 0:
            print(f"  → 총 {click_count}회 클릭 완료")

        return click_count

    # ========================================
    # 폼 자동 제출 (NEW!)
    # ========================================

    def submit_forms_with_test_data(self, forms: List[FormInfo]) -> Dict:
        """
        발견한 폼들에 테스트 데이터를 채워서 실제로 제출 (NEW!)

        Args:
            forms: 제출할 폼 리스트

        Returns:
            dict: 제출 결과
        """
        if not self.config.submit_forms:
            return {'submitted': 0, 'skipped': 0, 'errors': 0}

        print(f"[+] 폼 자동 제출 시작 (최대 {self.config.max_form_submissions}개)...")

        results = {
            'submitted_forms': [],
            'skipped_forms': [],
            'errors': []
        }

        # 원래 URL 저장
        original_url = self.page.url

        submit_count = 0

        for form_idx, form in enumerate(forms):
            if submit_count >= self.config.max_form_submissions:
                break

            try:
                # 위험한 폼 스킵
                if is_dangerous_url(form.action):
                    print(f"    [SKIP] 위험 폼: {form.action}")
                    results['skipped_forms'].append(form.action)
                    continue

                # 제출 가능한 필드가 없으면 스킵
                if not form.fields:
                    continue

                print(f"  [{form_idx + 1}] 폼 제출 시도: {form.method} {form.action}")

                # 각 필드에 값 채우기
                filled_fields = []
                for inp in form.fields:
                    # submit/button 타입은 스킵
                    if not inp.name or inp.input_type in ['submit', 'button', 'reset']:
                        continue

                    # 테스트 값 생성
                    test_value = inp.get_test_value()

                    # 필드에 값 입력
                    try:
                        selector = f'input[name="{inp.name}"], textarea[name="{inp.name}"], select[name="{inp.name}"]'

                        # select 요소
                        if inp.input_type in ['select-one', 'select-multiple']:
                            self.page.select_option(selector, index=0, timeout=2000)
                            filled_fields.append({'name': inp.name, 'value': '[첫 번째 옵션]'})
                        # checkbox/radio
                        elif inp.input_type in ['checkbox', 'radio']:
                            self.page.check(selector, timeout=2000)
                            filled_fields.append({'name': inp.name, 'value': 'checked'})
                        # 파일 업로드 - 스킵
                        elif inp.input_type == 'file':
                            print(f"      [SKIP] {inp.name} (파일 업로드는 스킵)")
                            continue
                        # 일반 input/textarea
                        else:
                            self.page.fill(selector, str(test_value), timeout=2000)
                            filled_fields.append({'name': inp.name, 'value': test_value})

                        print(f"      [OK] {inp.name} = {test_value}")

                    except Exception as fill_error:
                        print(f"      [X] {inp.name} 입력 실패")
                        results['errors'].append(f"Field fill error: {inp.name}")

                # 제출 버튼 찾기 및 클릭
                if filled_fields:
                    try:
                        submit_selectors = [
                            f'form:nth-of-type({form_idx + 1}) input[type="submit"]',
                            f'form:nth-of-type({form_idx + 1}) button[type="submit"]',
                            f'form:nth-of-type({form_idx + 1}) button',
                        ]

                        submitted = False
                        for selector in submit_selectors:
                            try:
                                if self.page.locator(selector).count() > 0:
                                    print(f"      [SUBMIT] 폼 제출 중...")
                                    self.page.click(selector, timeout=3000)
                                    self.page.wait_for_timeout(1500)
                                    submitted = True
                                    break
                            except:
                                continue

                        if submitted:
                            results['submitted_forms'].append({
                                'action': form.action,
                                'method': form.method,
                                'filled_fields': filled_fields,
                                'final_url': self.page.url
                            })
                            print(f"      [OK] 제출 완료!")
                            submit_count += 1
                        else:
                            print(f"      [X] 제출 버튼을 찾을 수 없음")

                        # 원래 페이지로 복원
                        if self.page.url != original_url:
                            print(f"      [RESTORE] 원래 페이지로 복원...")
                            self.page.goto(original_url, wait_until='networkidle')

                    except Exception as submit_error:
                        print(f"      [X] 제출 실패: {str(submit_error)[:50]}")
                        results['errors'].append(f"Submit error: {str(submit_error)[:50]}")
                        # 복원 시도
                        try:
                            if self.page.url != original_url:
                                self.page.goto(original_url, wait_until='networkidle')
                        except:
                            pass

            except Exception as e:
                print(f"    [ERROR] 폼 처리 오류: {str(e)[:50]}")
                results['errors'].append(f"Form process error: {str(e)[:50]}")

        print(f"  → 제출 완료: {len(results['submitted_forms'])}개")
        print(f"  → 스킵: {len(results['skipped_forms'])}개")
        print(f"  → 에러: {len(results['errors'])}개")

        return results

    # ========================================
    # 인터랙티브 요소 자동 클릭 (NEW!)
    # ========================================

    def trigger_interactive_elements(self) -> Dict:
        """
        발견한 모든 인터랙티브 요소를 자동으로 클릭 (NEW!)

        Returns:
            dict: 클릭 결과
        """
        if not self.config.trigger_elements:
            return {'clicked': 0, 'skipped': 0, 'errors': 0}

        print(f"[+] 인터랙티브 요소 자동 트리거 (최대 {self.config.max_element_clicks}개)...")

        results = {
            'clicked_elements': [],
            'skipped_elements': [],
            'errors': []
        }

        # 원래 URL 저장
        original_url = self.page.url
        click_count = 0
        max_clicks = self.config.max_element_clicks

        # 1. 버튼 클릭
        try:
            buttons = self.page.locator('button').all()
            print(f"  → 발견된 버튼: {len(buttons)}개")

            for i, button in enumerate(buttons):
                if click_count >= max_clicks:
                    break

                try:
                    button_text = button.inner_text().strip().lower()
                    button_type = button.get_attribute('type') or ''

                    # submit 버튼 스킵 (폼 제출과 중복)
                    if button_type == 'submit':
                        continue

                    # 위험한 버튼 필터링
                    if is_dangerous_url(button_text):
                        print(f"    [SKIP] 위험 버튼: '{safe_text(button_text)}'")
                        results['skipped_elements'].append(button_text)
                        continue

                    # 보이고 활성화된 버튼만
                    if not button.is_visible() or not button.is_enabled():
                        continue

                    print(f"    [CLICK] '{safe_text(button_text)}'")

                    button.click(timeout=3000)
                    click_count += 1
                    self.page.wait_for_timeout(1000)

                    results['clicked_elements'].append({'type': 'button', 'text': button_text})

                    # URL 변경 시 복원
                    if self.page.url != original_url:
                        print(f"    [RESTORE] 페이지 복원...")
                        self.page.goto(original_url, wait_until='networkidle')

                except Exception as e:
                    results['errors'].append(f"Button {i}: {str(e)[:50]}")

        except Exception as e:
            print(f"  [!] 버튼 처리 실패: {e}")

        # 2. 드롭다운 변경
        try:
            selects = self.page.locator('select').all()
            print(f"  → 발견된 드롭다운: {len(selects)}개")

            for i, select in enumerate(selects):
                if click_count >= max_clicks:
                    break

                try:
                    options = select.locator('option').all()
                    if len(options) <= 1:
                        continue

                    select_name = select.get_attribute('name') or f'select_{i}'

                    # 두 번째 옵션 선택
                    if len(options) > 1:
                        option_text = options[1].inner_text().strip()
                        option_value = options[1].get_attribute('value')

                        print(f"    [SELECT] '{select_name}' → '{option_text}'")

                        select.select_option(value=option_value)
                        click_count += 1
                        self.page.wait_for_timeout(1000)

                        results['clicked_elements'].append({'type': 'select', 'name': select_name, 'value': option_text})

                        # URL 변경 시 복원
                        if self.page.url != original_url:
                            self.page.goto(original_url, wait_until='networkidle')

                except Exception as e:
                    results['errors'].append(f"Select {i}: {str(e)[:50]}")

        except Exception as e:
            print(f"  [!] 드롭다운 처리 실패: {e}")

        print(f"  → 총 {click_count}개 요소 트리거 완료")
        print(f"  → 스킵: {len(results['skipped_elements'])}개")
        print(f"  → 에러: {len(results['errors'])}개")

        return results

    # ========================================
    # 민감정보 추출 (NEW!)
    # ========================================

    def extract_sensitive_data(self) -> List[SensitiveDataInfo]:
        """
        페이지의 모든 민감정보 추출 (통합 메서드)

        Returns:
            List[SensitiveDataInfo]: 발견된 민감정보 리스트
        """
        print("[+] 민감정보 탐지 시작...")

        all_sensitive_data = []

        try:
            # 1. 이메일
            all_sensitive_data.extend(self._extract_emails())

            # 2. 전화번호
            all_sensitive_data.extend(self._extract_phone_numbers())

            # 3. 신용카드
            all_sensitive_data.extend(self._extract_credit_cards())

            # 4. 주민번호/SSN
            all_sensitive_data.extend(self._extract_ssn())

            # 5. API 키
            all_sensitive_data.extend(self._extract_api_keys())

            # 6. JWT 토큰
            all_sensitive_data.extend(self._extract_jwt())

            # 7. 내부 IP
            all_sensitive_data.extend(self._extract_internal_ips())

            # 8. 스토리지 (localStorage/sessionStorage)
            all_sensitive_data.extend(self._extract_storage_data())

            # 9. data-* 속성
            all_sensitive_data.extend(self._extract_data_attributes())

            # 10. 테이블 데이터
            all_sensitive_data.extend(self._extract_table_data())

        except Exception as e:
            print(f"  [!] 민감정보 추출 중 오류: {e}")

        print(f"  → 발견된 민감정보: {len(all_sensitive_data)}개")
        return all_sensitive_data

    def _extract_emails(self) -> List[SensitiveDataInfo]:
        """페이지에서 이메일 주소 추출"""
        sensitive_data = []

        try:
            # DOM의 모든 텍스트 가져오기
            page_text = self.page.evaluate("() => document.body.innerText")

            # 정규식으로 이메일 찾기
            emails = re.findall(EMAIL_PATTERN, page_text)
            unique_emails = list(set(emails))[:10]  # 중복 제거, 최대 10개

            for email in unique_emails:
                # 각 이메일의 위치 찾기
                try:
                    location_info = self.page.evaluate(f"""
                        () => {{
                            const elements = Array.from(document.querySelectorAll('*'));
                            for (let elem of elements) {{
                                if (elem.childNodes.length === 1 &&
                                    elem.childNodes[0].nodeType === 3 &&
                                    elem.innerText &&
                                    elem.innerText.includes('{email}')) {{
                                    const selector = elem.tagName.toLowerCase() +
                                                   (elem.className ? '.' + elem.className.split(' ')[0] : '') +
                                                   (elem.id ? '#' + elem.id : '');
                                    return {{
                                        selector: selector,
                                        context: elem.innerText.substring(0, 100)
                                    }};
                                }}
                            }}
                            return {{selector: 'body', context: '{email}'}};
                        }}
                    """)

                    sensitive_data.append(SensitiveDataInfo(
                        data_type='email',
                        value=email,
                        location=location_info['selector'],
                        context=safe_text(location_info['context'][:100]),
                        page_url=self.page.url,
                        confidence=0.95
                    ))
                    print(f"    [EMAIL] {email}")

                except Exception:
                    pass

        except Exception as e:
            print(f"  [!] 이메일 추출 실패: {e}")

        return sensitive_data

    def _extract_phone_numbers(self) -> List[SensitiveDataInfo]:
        """페이지에서 전화번호 추출"""
        sensitive_data = []

        try:
            page_text = self.page.evaluate("() => document.body.innerText")

            # 각 전화번호 패턴으로 검색
            for pattern in PHONE_PATTERNS:
                phones = re.findall(pattern, page_text)
                unique_phones = list(set(phones))[:5]  # 중복 제거, 최대 5개

                for phone in unique_phones:
                    sensitive_data.append(SensitiveDataInfo(
                        data_type='phone',
                        value=phone,
                        location='body',
                        context=f"Phone: {phone}",
                        page_url=self.page.url,
                        confidence=0.9
                    ))
                    print(f"    [PHONE] {phone}")

        except Exception as e:
            print(f"  [!] 전화번호 추출 실패: {e}")

        return sensitive_data

    def _extract_credit_cards(self) -> List[SensitiveDataInfo]:
        """페이지에서 신용카드 번호 추출"""
        sensitive_data = []

        try:
            page_text = self.page.evaluate("() => document.body.innerText")
            cards = re.findall(CREDIT_CARD_PATTERN, page_text)
            unique_cards = list(set(cards))[:3]  # 중복 제거, 최대 3개

            for card in unique_cards:
                # 마스킹 처리
                masked = card[:4] + '-****-****-' + card[-4:]
                sensitive_data.append(SensitiveDataInfo(
                    data_type='credit_card',
                    value=masked,
                    location='body',
                    context=f"Card: {masked}",
                    page_url=self.page.url,
                    confidence=0.85
                ))
                print(f"    [CARD] {masked}")

        except Exception as e:
            print(f"  [!] 신용카드 추출 실패: {e}")

        return sensitive_data

    def _extract_ssn(self) -> List[SensitiveDataInfo]:
        """페이지에서 주민번호/SSN 추출"""
        sensitive_data = []

        try:
            page_text = self.page.evaluate("() => document.body.innerText")
            ssns = re.findall(SSN_PATTERN, page_text)
            unique_ssns = list(set(ssns))[:3]  # 중복 제거, 최대 3개

            for ssn in unique_ssns:
                # 마스킹 처리
                masked = ssn[:6] + '-*******'
                sensitive_data.append(SensitiveDataInfo(
                    data_type='ssn',
                    value=masked,
                    location='body',
                    context=f"SSN: {masked}",
                    page_url=self.page.url,
                    confidence=0.8
                ))
                print(f"    [SSN] {masked}")

        except Exception as e:
            print(f"  [!] SSN 추출 실패: {e}")

        return sensitive_data

    def _extract_api_keys(self) -> List[SensitiveDataInfo]:
        """페이지에서 API 키 추출"""
        sensitive_data = []

        try:
            page_text = self.page.evaluate("() => document.body.innerText + document.body.innerHTML")

            for pattern in API_KEY_PATTERNS:
                keys = re.findall(pattern, page_text)
                unique_keys = list(set(keys))[:5]  # 중복 제거, 최대 5개

                for key in unique_keys:
                    # 마스킹 처리
                    masked = key[:10] + '***' + key[-4:] if len(key) > 14 else key[:5] + '***'
                    sensitive_data.append(SensitiveDataInfo(
                        data_type='api_key',
                        value=masked,
                        location='body/script',
                        context=f"API Key: {masked}",
                        page_url=self.page.url,
                        confidence=0.9
                    ))
                    print(f"    [API_KEY] {masked}")

        except Exception as e:
            print(f"  [!] API 키 추출 실패: {e}")

        return sensitive_data

    def _extract_jwt(self) -> List[SensitiveDataInfo]:
        """페이지에서 JWT 토큰 추출"""
        sensitive_data = []

        try:
            page_text = self.page.evaluate("() => document.body.innerText + document.body.innerHTML")
            jwts = re.findall(JWT_PATTERN, page_text)
            unique_jwts = list(set(jwts))[:3]  # 중복 제거, 최대 3개

            for jwt in unique_jwts:
                # 마스킹 처리
                masked = jwt[:20] + '...' + jwt[-20:]
                sensitive_data.append(SensitiveDataInfo(
                    data_type='jwt',
                    value=masked,
                    location='body/script',
                    context=f"JWT: {masked}",
                    page_url=self.page.url,
                    confidence=0.95
                ))
                print(f"    [JWT] {masked[:30]}...")

        except Exception as e:
            print(f"  [!] JWT 추출 실패: {e}")

        return sensitive_data

    def _extract_internal_ips(self) -> List[SensitiveDataInfo]:
        """페이지에서 내부 IP 주소 추출"""
        sensitive_data = []

        try:
            page_text = self.page.evaluate("() => document.body.innerText")

            for pattern in INTERNAL_IP_PATTERNS:
                ips = re.findall(pattern, page_text)
                unique_ips = list(set(ips))[:5]  # 중복 제거, 최대 5개

                for ip in unique_ips:
                    sensitive_data.append(SensitiveDataInfo(
                        data_type='internal_ip',
                        value=ip,
                        location='body',
                        context=f"Internal IP: {ip}",
                        page_url=self.page.url,
                        confidence=0.9
                    ))
                    print(f"    [INTERNAL_IP] {ip}")

        except Exception as e:
            print(f"  [!] 내부 IP 추출 실패: {e}")

        return sensitive_data

    def _extract_storage_data(self) -> List[SensitiveDataInfo]:
        """브라우저 스토리지에서 민감정보 추출"""
        sensitive_data = []

        try:
            storage_data = self.page.evaluate("""
                () => {
                    const data = [];

                    // localStorage 스캔
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        const value = localStorage.getItem(key);
                        data.push({type: 'localStorage', key: key, value: value});
                    }

                    // sessionStorage 스캔
                    for (let i = 0; i < sessionStorage.length; i++) {
                        const key = sessionStorage.key(i);
                        const value = sessionStorage.getItem(key);
                        data.push({type: 'sessionStorage', key: key, value: value});
                    }

                    return data;
                }
            """)

            for item in storage_data[:10]:  # 최대 10개
                key_lower = item['key'].lower()
                value = item['value']

                # 민감한 키워드 감지
                if any(keyword in key_lower for keyword in ['api', 'key', 'token', 'secret', 'password', 'session', 'auth']):
                    masked = value[:10] + '***' if len(value) > 10 else value
                    sensitive_data.append(SensitiveDataInfo(
                        data_type='storage',
                        value=masked,
                        location=f"{item['type']}['{item['key']}']",
                        context=f"{item['type']}: {item['key']}",
                        page_url=self.page.url,
                        confidence=0.8
                    ))
                    print(f"    [STORAGE] {item['type']}.{item['key']}")

        except Exception as e:
            print(f"  [!] 스토리지 추출 실패: {e}")

        return sensitive_data

    def _extract_data_attributes(self) -> List[SensitiveDataInfo]:
        """data-* 속성에서 민감정보 추출"""
        sensitive_data = []

        try:
            attributes = self.page.evaluate("""
                () => {
                    const data = [];
                    const elements = document.querySelectorAll('[data-user-id], [data-api-key], [data-token], [data-email], [data-user], [data-id]');

                    elements.forEach(elem => {
                        for (let attr of elem.attributes) {
                            if (attr.name.startsWith('data-')) {
                                data.push({
                                    attribute: attr.name,
                                    value: attr.value,
                                    tagName: elem.tagName
                                });
                            }
                        }
                    });

                    return data;
                }
            """)

            for attr in attributes[:10]:  # 최대 10개
                # 민감한 속성명 감지
                if any(keyword in attr['attribute'] for keyword in ['user', 'id', 'token', 'key', 'email', 'api']):
                    sensitive_data.append(SensitiveDataInfo(
                        data_type='data_attribute',
                        value=attr['value'],
                        location=f"{attr['tagName'].lower()}[{attr['attribute']}]",
                        context=f"Attribute: {attr['attribute']}={attr['value']}",
                        page_url=self.page.url,
                        confidence=0.7
                    ))
                    print(f"    [DATA_ATTR] {attr['attribute']}={attr['value']}")

        except Exception as e:
            print(f"  [!] data-* 속성 추출 실패: {e}")

        return sensitive_data

    def _extract_table_data(self) -> List[SensitiveDataInfo]:
        """테이블에서 사용자 정보 추출"""
        sensitive_data = []

        try:
            tables = self.page.evaluate("""
                () => {
                    const tables = [];
                    document.querySelectorAll('table').forEach((table, idx) => {
                        const headers = Array.from(table.querySelectorAll('th')).map(th => th.innerText);
                        const rows = [];

                        table.querySelectorAll('tbody tr').forEach(tr => {
                            const cells = Array.from(tr.querySelectorAll('td')).map(td => td.innerText);
                            if (cells.length > 0) {
                                rows.push(cells);
                            }
                        });

                        if (headers.length > 0 && rows.length > 0) {
                            tables.push({headers: headers, rows: rows, tableIndex: idx});
                        }
                    });

                    return tables;
                }
            """)

            for table in tables[:3]:  # 최대 3개 테이블
                headers = [h.lower() for h in table['headers']]

                # 민감한 컬럼 감지 (email, phone, username 등)
                if any(keyword in ' '.join(headers) for keyword in ['email', 'phone', 'username', 'user', 'id', 'password']):
                    for row_idx, row in enumerate(table['rows'][:3]):  # 처음 3개 행만
                        for col_idx, cell in enumerate(row):
                            # 이메일 패턴 체크
                            if re.match(EMAIL_PATTERN, cell):
                                sensitive_data.append(SensitiveDataInfo(
                                    data_type='table_data',
                                    value=cell,
                                    location=f"table[{table['tableIndex']}] row[{row_idx}] col[{col_idx}]",
                                    context=f"Header: {table['headers'][col_idx]}",
                                    page_url=self.page.url,
                                    confidence=0.9
                                ))
                                print(f"    [TABLE] {table['headers'][col_idx]}: {cell}")

        except Exception as e:
            print(f"  [!] 테이블 데이터 추출 실패: {e}")

        return sensitive_data


# ========================================
# 보안 분석 클래스
# ========================================

class SecurityAnalyzer:
    """
    보안 설정 분석 기능

    주요 기능:
    - CSP (Content Security Policy) 분석
    - HttpOnly 쿠키 확인
    - 보안 헤더 검사
    - XSS 취약점 사전 탐지
    """

    def __init__(self, page: Page, context: BrowserContext):
        """
        Args:
            page: Playwright Page 객체
            context: Playwright BrowserContext 객체
        """
        self.page = page
        self.context = context

    def analyze_page_security(self, url: str, response_headers: Optional[Dict[str, str]] = None) -> SecurityInfo:
        """
        페이지의 보안 설정 분석

        Args:
            url: 분석할 URL
            response_headers: HTTP 응답 헤더

        Returns:
            SecurityInfo: 보안 분석 결과
        """
        print(f"[+] 보안 분석 시작: {url}")

        security_info = SecurityInfo(url=url)

        # ========================================
        # 1. CSP 확인
        # ========================================

        # HTTP 헤더에서 CSP 확인
        if response_headers:
            csp = response_headers.get('content-security-policy') or response_headers.get('x-content-security-policy')
            if csp:
                security_info.csp = csp
                security_info.csp_source = 'http_header'

        # Meta 태그에서 CSP 확인
        if not security_info.csp:
            try:
                csp_meta = self.page.evaluate("""() => {
                    const meta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
                    return meta ? meta.content : null;
                }""")
                if csp_meta:
                    security_info.csp = csp_meta
                    security_info.csp_source = 'meta_tag'
            except:
                pass

        # CSP 분석
        if security_info.csp:
            print(f"  → [CSP 발견] (출처: {security_info.csp_source})")
            security_info.csp_parsed = self._parse_csp(security_info.csp)
            security_info.csp_issues = self._analyze_csp_weaknesses(security_info.csp_parsed)

            if security_info.csp_issues:
                for issue in security_info.csp_issues[:3]:  # 최대 3개만 출력
                    print(f"    [!] {issue}")
            else:
                print(f"    [OK] CSP 설정 양호")
        else:
            print(f"  → [CSP 없음] [WARNING] XSS 공격에 취약할 수 있음")
            security_info.csp_issues.append("CSP 미설정 - XSS 공격 방어 없음")

        # ========================================
        # 2. 보안 헤더 확인
        # ========================================

        if response_headers:
            security_headers = {
                'X-Frame-Options': response_headers.get('x-frame-options'),
                'X-Content-Type-Options': response_headers.get('x-content-type-options'),
                'Strict-Transport-Security': response_headers.get('strict-transport-security'),
                'X-XSS-Protection': response_headers.get('x-xss-protection'),
                'Referrer-Policy': response_headers.get('referrer-policy')
            }
            security_info.security_headers = {k: v for k, v in security_headers.items() if v}

            missing_headers = [k for k, v in security_headers.items() if not v]
            if missing_headers:
                print(f"  → [보안 헤더 누락]: {', '.join(missing_headers[:3])}")

        # ========================================
        # 3. HttpOnly 쿠키 확인
        # ========================================

        # JavaScript로 접근 가능한 쿠키
        try:
            js_cookies = self.page.evaluate("document.cookie")
            security_info.js_accessible_cookies = js_cookies
            if js_cookies:
                print(f"  → [JS 접근 가능 쿠키]: {js_cookies[:50]}...")
            else:
                print(f"  → [JS 접근 가능 쿠키]: (없음)")
        except:
            security_info.js_accessible_cookies = None

        # 모든 쿠키 분석
        try:
            all_cookies = self.context.cookies()
            print(f"  → [쿠키 분석]: 총 {len(all_cookies)}개")

            for cookie in all_cookies:
                cookie_info = {
                    'name': cookie['name'],
                    'value': cookie['value'][:20] + '...' if len(cookie['value']) > 20 else cookie['value'],
                    'domain': cookie.get('domain', ''),
                    'path': cookie.get('path', '/'),
                    'httpOnly': cookie.get('httpOnly', False),
                    'secure': cookie.get('secure', False),
                    'sameSite': cookie.get('sameSite', 'None')
                }

                security_info.cookies.append(cookie_info)

                # 세션 쿠키 확인
                if self._is_session_cookie(cookie['name']):
                    if not cookie.get('httpOnly', False):
                        security_info.vulnerable_cookies.append(cookie_info)
                        print(f"    [VULN] {cookie['name']}: HttpOnly [NO]")
                    else:
                        print(f"    [SAFE] {cookie['name']}: HttpOnly [OK]")

        except Exception as e:
            print(f"  [!] 쿠키 분석 실패: {e}")

        return security_info

    def _parse_csp(self, csp_string: str) -> Dict[str, List[str]]:
        """CSP 문자열 파싱"""
        policy = {}
        directives = csp_string.split(';')

        for directive in directives:
            parts = directive.strip().split()
            if parts:
                key = parts[0]
                values = parts[1:] if len(parts) > 1 else []
                policy[key] = values

        return policy

    def _analyze_csp_weaknesses(self, csp_parsed: Dict[str, List[str]]) -> List[str]:
        """CSP 취약점 분석"""
        issues = []

        # script-src 분석
        script_src = csp_parsed.get('script-src', [])
        if "'unsafe-inline'" in script_src:
            issues.append("script-src에 'unsafe-inline' 허용 → XSS 위험")

        if "'unsafe-eval'" in script_src:
            issues.append("script-src에 'unsafe-eval' 허용 → 코드 인젝션 위험")

        if '*' in script_src:
            issues.append("script-src에 와일드카드(*) 허용 → 매우 위험")

        if 'data:' in script_src:
            issues.append("script-src에 data: URI 허용 → base64 스크립트 실행 가능")

        # default-src 확인
        if 'default-src' not in csp_parsed:
            issues.append("default-src 미설정 → 기본 정책 없음")

        # object-src 확인
        object_src = csp_parsed.get('object-src', [])
        if "'none'" not in object_src and object_src:
            issues.append("object-src 미제한 → Flash/플러그인 삽입 가능")

        # base-uri 확인
        if 'base-uri' not in csp_parsed:
            issues.append("base-uri 미설정 → base 태그 인젝션 가능")

        return issues

    def _is_session_cookie(self, cookie_name: str) -> bool:
        """세션 쿠키 판별"""
        keywords = ['session', 'sess', 'auth', 'token', 'login', 'sid',
                   'phpsessid', 'jsessionid', 'asp.net_sessionid']
        return any(k in cookie_name.lower() for k in keywords)


# ========================================
# 메인 크롤러 클래스
# ========================================

class XSSCrawler:
    """
    XSS 퍼저용 통합 크롤러

    주요 기능:
    - 재귀적 웹 크롤링
    - 폼/API 엔드포인트 수집
    - XSS 인젝션 포인트 자동 탐지
    - 보안 설정 분석
    - 동적 콘텐츠 처리
    - 폼 자동 제출 (NEW!)
    - 인터랙티브 요소 자동 클릭 (NEW!)
    - 크롤링 결과 JSON 저장
    """

    def __init__(self, config: CrawlerConfig):
        """
        Args:
            config: 크롤러 설정
        """
        self.config = config
        self.browser = BrowserController(config)
        self.visited_urls: Set[str] = set()        # 이미 방문한 URL (정규화됨)
        self.queued_urls: Set[str] = set()         # to_visit 큐에 대기 중인 URL (중복 방지)
        self.to_visit: List[tuple] = []            # (url, depth)
        self.result: Optional[CrawlResult] = None

    def login(self) -> bool:
        """
        자동 로그인 수행

        Returns:
            bool: 로그인 성공 여부
        """
        if not self.config.login_url or not self.config.username:
            return False

        print(f"[+] 로그인 시도: {self.config.login_url}")

        if not self.browser.navigate(self.config.login_url):
            return False

        # 일반적인 로그인 폼 선택자 시도
        username_selectors = [
            'input[name="username"]', 'input[name="user"]',
            'input[name="email"]', 'input[type="text"]', 'input[id="username"]'
        ]

        password_selectors = [
            'input[name="password"]', 'input[type="password"]', 'input[id="password"]'
        ]

        # Username 입력
        username_filled = False
        for selector in username_selectors:
            if self.browser.fill(selector, self.config.username):
                username_filled = True
                break

        if not username_filled:
            print("[!] Username 필드를 찾을 수 없습니다")
            return False

        # Password 입력
        password_filled = False
        for selector in password_selectors:
            if self.browser.fill(selector, self.config.password):
                password_filled = True
                break

        if not password_filled:
            print("[!] Password 필드를 찾을 수 없습니다")
            return False

        # 로그인 버튼 클릭
        submit_selectors = [
            'button[type="submit"]', 'input[type="submit"]',
            'button:has-text("로그인")', 'button:has-text("Login")'
        ]

        for selector in submit_selectors:
            if self.browser.click(selector):
                time.sleep(1)  # 로그인 처리 대기 (최적화: 2초 → 1초)
                print("[+] 로그인 완료")
                return True

        print("[!] 로그인 버튼을 찾을 수 없습니다")
        return False

    def crawl(self, start_url: str) -> CrawlResult:
        """
        크롤링 시작

        Args:
            start_url: 시작 URL

        Returns:
            CrawlResult: 크롤링 결과
        """
        print(f"\n{'='*60}")
        print(f"XSS Crawler 시작")
        print(f"시작 URL: {start_url}")
        print(f"최대 깊이: {self.config.max_depth}")
        print(f"최대 페이지: {self.config.max_pages}")
        if self.config.submit_forms:
            print(f"폼 자동 제출: 활성화 (최대 {self.config.max_form_submissions}개)")
        if self.config.trigger_elements:
            print(f"요소 자동 클릭: 활성화 (최대 {self.config.max_element_clicks}개)")
        print(f"{'='*60}\n")

        # 결과 객체 초기화
        self.result = CrawlResult(base_url=start_url)

        # 브라우저 시작
        self.browser.start()

        # 로그인 수행 (설정된 경우)
        if self.config.login_url:
            self.login()

        # 크롤링 시작
        start_url_normalized = normalize_url(start_url)
        self.to_visit.append((start_url, 0))
        self.queued_urls.add(start_url_normalized)

        while self.to_visit and len(self.visited_urls) < self.config.max_pages:
            url, depth = self.to_visit.pop(0)

            # URL 정규화 (중복 방지)
            normalized_url = normalize_url(url)

            # 이미 방문한 URL은 스킵
            if normalized_url in self.visited_urls:
                continue

            # 깊이 제한 확인
            if depth > self.config.max_depth:
                continue

            # 제외할 확장자 확인
            if any(url.lower().endswith(ext) for ext in self.config.exclude_extensions):
                continue

            # 위험한 URL 제외 (로그아웃, CAPTCHA 등)
            if is_dangerous_url(url):
                continue

            print(f"\n[크롤링] (깊이 {depth}) {url}")

            # 페이지 방문
            if not self._crawl_page(url, depth):
                self.result.errors.append(f"페이지 로드 실패: {url}")
                continue

            # 정규화된 URL로 저장 (중복 방지)
            self.visited_urls.add(normalized_url)
            self.result.crawled_urls.append(url)

        # 크롤링 완료
        self.result.finalize()
        self.browser.close()

        # 결과 출력
        self._print_summary()

        return self.result

    def _crawl_page(self, url: str, depth: int) -> bool:
        """
        단일 페이지 크롤링

        Args:
            url: 크롤링할 URL
            depth: 현재 깊이

        Returns:
            bool: 성공 여부
        """
        # 페이지 이동
        if not self.browser.navigate(url):
            return False

        # 네트워크 캡처 시작
        network = NetworkCapture(self.browser.page, self.result.base_url)

        # DOM 분석 시작
        dom = DOMAnalyzer(self.browser.page, self.result.base_url, self.config)

        # DOM 통계 수집
        dom.get_dom_stats()

        # 동적 콘텐츠 처리
        dom.handle_infinite_scroll()
        dom.handle_load_more_button()

        # 폼 추출
        forms = dom.extract_forms()
        for form in forms:
            self.result.add_form(form)

        # 폼 자동 제출 (NEW!)
        if self.config.submit_forms and forms:
            dom.submit_forms_with_test_data(forms)

        # 인터랙티브 요소 자동 클릭 (NEW!)
        if self.config.trigger_elements:
            dom.trigger_interactive_elements()

        # 링크 추출 (다음 크롤링 대상)
        links = dom.extract_links()
        for link in links:
            # URL 정규화 (중복 방지)
            normalized_link = normalize_url(link)

            # 이미 방문했거나 큐에 대기 중인 URL은 스킵
            if normalized_link not in self.visited_urls and normalized_link not in self.queued_urls:
                self.to_visit.append((link, depth + 1))
                self.queued_urls.add(normalized_link)  # 큐에 추가된 것으로 표시

        # 페이지 로딩 대기 (네트워크 요청 캡처 위해)
        time.sleep(0.3)  # 최적화: 1초 → 0.3초

        # 엔드포인트 추출
        endpoints = network.get_endpoints()
        for endpoint in endpoints:
            self.result.add_endpoint(endpoint)

        # 보안 분석
        security_analyzer = SecurityAnalyzer(self.browser.page, self.browser.context)
        response_headers = network.get_page_response_headers()
        security_report = security_analyzer.analyze_page_security(url, response_headers)
        self.result.add_security_report(security_report)

        # 민감정보 추출 (NEW!)
        sensitive_data_list = dom.extract_sensitive_data()
        for sensitive_data in sensitive_data_list:
            self.result.add_sensitive_data(sensitive_data)

        return True

    def _print_summary(self):
        """크롤링 결과 요약 출력"""
        print(f"\n{'='*60}")
        print(f"크롤링 완료!")
        print(f"{'='*60}")
        print(f"총 페이지: {len(self.result.crawled_urls)}")
        print(f"총 폼: {len(self.result.forms)}")
        print(f"총 엔드포인트: {len(self.result.endpoints)}")
        print(f"총 인젝션 포인트: {len(self.result.injection_points)}")

        stats = self.result.to_dict()['statistics']
        print(f"\n[인젝션 포인트 분류]")
        print(f"  - 폼 필드: {stats['form_injection_points']}개")
        print(f"  - URL 파라미터: {stats['url_param_injection_points']}개")
        print(f"  - POST 파라미터: {stats['post_param_injection_points']}개")
        print(f"  - 파일 업로드: {stats['file_upload_injection_points']}개")

        print(f"\n[보안 분석]")
        print(f"  - 보안 리포트: {len(self.result.security_reports)}개")
        print(f"  - CSP 있는 페이지: {stats['pages_with_csp']}개")
        print(f"  - 취약한 쿠키: {stats['vulnerable_cookies']}개")

        vulnerable_pages = sum(1 for r in self.result.security_reports if r.csp_issues or r.vulnerable_cookies)
        if vulnerable_pages > 0:
            print(f"  [VULN] 취약한 페이지: {vulnerable_pages}개")

        print(f"\n[민감정보 탐지]")
        print(f"  - 총 민감정보: {stats['total_sensitive_data']}개")
        sensitive_by_type = stats['sensitive_data_by_type']
        if sensitive_by_type['email'] > 0:
            print(f"    - 이메일: {sensitive_by_type['email']}개")
        if sensitive_by_type['phone'] > 0:
            print(f"    - 전화번호: {sensitive_by_type['phone']}개")
        if sensitive_by_type['credit_card'] > 0:
            print(f"    - 신용카드: {sensitive_by_type['credit_card']}개")
        if sensitive_by_type['ssn'] > 0:
            print(f"    - 주민번호/SSN: {sensitive_by_type['ssn']}개")
        if sensitive_by_type['api_key'] > 0:
            print(f"    - API 키: {sensitive_by_type['api_key']}개")
        if sensitive_by_type['jwt'] > 0:
            print(f"    - JWT 토큰: {sensitive_by_type['jwt']}개")
        if sensitive_by_type['internal_ip'] > 0:
            print(f"    - 내부 IP: {sensitive_by_type['internal_ip']}개")
        if sensitive_by_type['storage'] > 0:
            print(f"    - 브라우저 스토리지: {sensitive_by_type['storage']}개")
        if sensitive_by_type['data_attribute'] > 0:
            print(f"    - data-* 속성: {sensitive_by_type['data_attribute']}개")
        if sensitive_by_type['table_data'] > 0:
            print(f"    - 테이블 데이터: {sensitive_by_type['table_data']}개")

        print(f"{'='*60}\n")


# ========================================
# 사용 예시
# ========================================

if __name__ == "__main__":
    # 크롤러 설정
    config = CrawlerConfig(
        headless=False,                # 브라우저 표시
        max_depth=2,                   # 최대 2단계까지 크롤링
        max_pages=50,                  # 최대 10페이지
        timeout=10000,                 # 10초 타임아웃

        # 동적 콘텐츠 처리
        handle_infinite_scroll=True,   # 무한 스크롤 처리
        max_scrolls=3,                 # 최대 3회 스크롤
        handle_load_more=True,         # 더보기 버튼 처리
        max_load_more_clicks=3,        # 최대 3회 클릭

        # 폼 자동 제출 (NEW!)
        submit_forms=True,            # 폼 자동 제출 (위험할 수 있음!)
        max_form_submissions=3,        # 최대 3개 폼만 제출

        # 인터랙티브 요소 자동 클릭 (NEW!)
        trigger_elements=True,        # 요소 자동 클릭 (위험할 수 있음!)
        max_element_clicks=5,          # 최대 5개 요소만 클릭

        # 로그인이 필요한 경우
        login_url="http://192.168.204.128/dvwa/login.php",
        username="admin",
        password="password"
    )

    # 크롤러 생성 및 실행
    crawler = XSSCrawler(config)
    result = crawler.crawl("http://192.168.204.128/dvwa/")

    # 결과 저장
    result.save_to_json("xss_crawl_result.json")

    # 인젝션 포인트 출력
    print("\n[XSS 인젝션 포인트 샘플]")
    for idx, point in enumerate(result.injection_points[:10], 1):  # 처음 10개만
        print(f"{idx}. [{point.point_type}] {point.method} {point.url}")
        print(f"   파라미터: {point.parameter_name}")
        print(f"   테스트 값: {point.test_value}")

    # 보안 이슈 요약
    print("\n[보안 이슈 샘플]")
    for report in result.security_reports[:3]:  # 처음 3개만
        if report.csp_issues or report.vulnerable_cookies:
            print(f"\n[PAGE] {report.url}")
            for issue in report.csp_issues[:2]:
                print(f"  [!] {issue}")
            for cookie in report.vulnerable_cookies[:2]:
                print(f"  [!] 쿠키 '{cookie['name']}': HttpOnly 미설정")
