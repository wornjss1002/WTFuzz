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
9. 민감정보 탐지 (이메일, 전화번호, API 키, JWT 등)
10. 자동 로그인
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
        '.css', '.js', '.woff', '.ttf', '.svg', '.md'
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

    def detect_sensitive_type(self) -> Optional[str]:
        """
        민감정보 필드 타입 탐지

        탐지 가능한 타입:
        - credit_card: 신용카드
        - password: 비밀번호
        - ssn: 주민등록번호/사회보장번호
        - bank_account: 계좌번호
        - passport: 여권번호
        - phone: 전화번호
        - email: 이메일

        Returns:
            민감정보 타입 문자열 또는 None
        """
        name_lower = self.name.lower()
        type_lower = self.input_type.lower()

        # 1. Password (최우선 - type으로 명확)
        if type_lower == 'password':
            return 'password'

        # 2. Email (type으로 명확)
        if type_lower == 'email':
            return 'email'

        # 3. Phone (type='tel' 또는 name 패턴)
        if type_lower == 'tel':
            return 'phone'
        if any(keyword in name_lower for keyword in ['phone', 'tel', 'mobile', 'cell', '전화', '휴대폰']):
            return 'phone'

        # 4. Credit Card (name 패턴 + pattern 또는 maxlength)
        if any(keyword in name_lower for keyword in ['card', 'cc', 'credit', 'creditcard', 'cardnumber']):
            # pattern이나 maxlength로 추가 검증
            if self.pattern and any(p in self.pattern for p in ['16', '19', r'\d{16}', r'\d{4}']):
                return 'credit_card'
            if self.max_length in [16, 19]:
                return 'credit_card'
            # name만으로도 충분히 의심되면 반환
            if 'card' in name_lower or 'creditcard' in name_lower:
                return 'credit_card'

        # 5. SSN (name 패턴)
        # 'security'는 너무 일반적이라 제외, 더 구체적인 키워드만 사용
        if any(keyword in name_lower for keyword in ['ssn', 'social_security', 'socialsecurity', 'resident', 'jumin', '주민', 'social-security']):
            return 'ssn'

        # 6. Bank Account (name 패턴)
        if any(keyword in name_lower for keyword in ['account', 'bank', 'bankaccount', 'accountnumber', '계좌']):
            # 너무 일반적인 단어라서 추가 검증
            if self.max_length >= 10:  # 계좌번호는 보통 10자리 이상
                return 'bank_account'
            if 'bank' in name_lower or '계좌' in name_lower:
                return 'bank_account'

        # 7. Passport (name 패턴)
        if any(keyword in name_lower for keyword in ['passport', '여권']):
            return 'passport'

        return None


@dataclass
class FormInfo:
    """HTML 폼 정보"""
    action: str                               # 폼 액션 URL
    method: str                               # HTTP 메서드
    fields: List[InputField]                  # 입력 필드 리스트
    form_id: str = ""                         # 폼 ID
    form_name: str = ""                       # 폼 이름
    enctype: str = ""                         # 인코딩 타입
    source_url: str = ""                      # 폼이 발견된 실제 페이지 URL

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
        Hidden 필드 분석 - CSRF 토큰 등 구분
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
    js_accessible_cookies: List[Dict[str, Any]] = field(default_factory=list)  # XSS로 탈취 가능한 쿠키 (파싱 완료)
    exposed_secrets: List[Dict[str, Any]] = field(default_factory=list)  # 페이지에 노출된 민감 데이터 (API 키, JWT 등)
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
class CrawlResult:
    """크롤링 결과"""
    base_url: str
    crawled_urls: List[str] = field(default_factory=list)
    forms: List[FormInfo] = field(default_factory=list)
    endpoints: List[Endpoint] = field(default_factory=list)
    injection_points: List[InjectionPoint] = field(default_factory=list)
    security_reports: List[SecurityInfo] = field(default_factory=list)
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

        # 파일 업로드 필드        for field_info in form.get_file_upload_fields():
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

    def finalize(self):
        """크롤링 완료 처리"""
        self.end_time = datetime.now().isoformat()


# ========================================
# 익스플로잇 정보 수집 클래스
# ========================================

class ExploitInfoCollector:
    """
    5가지 익스플로잇 정보 수집 전담 클래스

    친구의 익스플로잇 모듈에 필요한 정보를 수집합니다:
    1. 쿠키 탈취
    2. 민감정보 탈취
    3. 키로거
    4. 피싱
    5. 권한 악용
    """

    def __init__(self, crawl_result: 'CrawlResult', page: Optional[Page] = None, context: Optional['BrowserContext'] = None):
        """
        Args:
            crawl_result: 크롤링 결과 데이터
            page: Playwright Page 객체 (크롤링 중 직접 수집용)
            context: Playwright BrowserContext 객체 (쿠키 보안 속성 분석용)
        """
        self.result = crawl_result
        self.page = page
        self.context = context

    def collect_all(self, url: str) -> dict:
        """
        특정 URL의 모든 익스플로잇 정보 수집

        Args:
            url: 타겟 URL

        Returns:
            dict: 5가지 익스플로잇 정보
        """
        return {
            '1_cookie_theft': self.get_cookie_theft_info(url),
            '2_sensitive_data': self.get_sensitive_data_info(url),
            '3_keylogger': self.get_keylogger_info(url),
            '4_phishing': self.get_phishing_info(url),
            '5_permission_abuse': self.get_permission_info(url)
        }

    def get_cookie_theft_info(self, url: str) -> dict:
        """
        1. 쿠키 탈취 익스플로잇 정보 + 쿠키 보안 속성 분석

        페이지가 열려있으면:
        - document.cookie로 JS 접근 가능한 쿠키 수집
        - context.cookies()로 모든 쿠키의 보안 속성 분석

        페이지가 없으면 저장된 security_report에서 가져오기

        Returns:
            dict: {
                'stealable_cookies': [JS 접근 가능한 쿠키 리스트],
                'all_cookies': [모든 쿠키의 보안 속성 리스트],
                'exploit_available': True/False
            }
        """
        stealable_cookies = []
        all_cookies = []

        # 방법 1: 페이지가 열려있으면 직접 수집
        if self.page and self.context:
            try:
                print("[+] 쿠키 종합 분석 중 (ExploitInfoCollector)...")

                # 1. document.cookie로 JS 접근 가능한 쿠키 수집
                cookies_data = self.page.evaluate("""
                    () => {
                        const cookieString = document.cookie;
                        const cookies = [];

                        if (cookieString && cookieString.trim() !== '') {
                            cookieString.split(';').forEach(cookie => {
                                const parts = cookie.trim().split('=');
                                if (parts.length >= 2) {
                                    const name = parts[0].trim();
                                    const value = parts.slice(1).join('=').trim();

                                    cookies.push({
                                        name: name,
                                        value: value,
                                        accessible_via_js: true,
                                        source: 'document.cookie'
                                    });
                                }
                            });
                        }

                        return cookies;
                    }
                """)

                stealable_cookies = cookies_data

                # 2. context.cookies()로 모든 쿠키의 보안 속성 분석
                from urllib.parse import urlparse
                current_domain = urlparse(url).netloc

                all_context_cookies = self.context.cookies()
                domain_cookies = [
                    cookie for cookie in all_context_cookies
                    if current_domain in cookie.get('domain', '')
                ]

                vulnerable_count = 0
                for cookie in domain_cookies:
                    cookie_name = cookie.get('name', 'unknown')
                    http_only = cookie.get('httpOnly', False)
                    secure = cookie.get('secure', False)
                    same_site = cookie.get('sameSite', 'None')

                    # 보안 이슈 체크
                    issues = []
                    if not http_only:
                        issues.append('HttpOnly=False (XSS로 탈취 가능)')
                        vulnerable_count += 1
                    if not secure:
                        issues.append('Secure=False')
                    if same_site == 'None' or not same_site:
                        issues.append('SameSite=None (CSRF 위험)')

                    all_cookies.append({
                        'name': cookie_name,
                        'domain': cookie.get('domain', ''),
                        'path': cookie.get('path', '/'),
                        'httpOnly': http_only,
                        'secure': secure,
                        'sameSite': same_site,
                        'expires': cookie.get('expires', -1),
                        'value': cookie.get('value', '')[:20] + '...' if len(cookie.get('value', '')) > 20 else cookie.get('value', ''),
                        'vulnerable': len(issues) > 0,
                        'issues': issues
                    })

                    # 취약한 쿠키 출력
                    if issues:
                        print(f"    [!] {safe_text(cookie_name)}: {', '.join(issues)}")

                if stealable_cookies:
                    print(f"  → [쿠키] {len(stealable_cookies)}개 JS 접근 가능 쿠키 발견")
                else:
                    print(f"  → [쿠키] JS 접근 가능 쿠키 없음 (모두 HttpOnly=true)")

                if vulnerable_count > 0:
                    print(f"  → [경고] {vulnerable_count}개 취약한 쿠키 발견")

            except Exception as e:
                print(f"  [!] 쿠키 분석 실패: {str(e)}")

        # 방법 2: 페이지가 없으면 저장된 데이터에서 가져오기
        else:
            for report in self.result.security_reports:
                if normalize_url(report.url) == normalize_url(url):
                    stealable_cookies = report.js_accessible_cookies
                    all_cookies = report.cookies
                    break

        return {
            'stealable_cookies': stealable_cookies,
            'all_cookies': all_cookies,
            'exploit_available': len(stealable_cookies) > 0
        }

    def get_exposed_secrets_info(self, url: str) -> dict:
        """
        노출된 시크릿 수집 (API 키, JWT, 토큰 등)

        페이지가 열려있으면 직접 수집
        페이지가 없으면 저장된 security_report에서 가져오기

        Returns:
            dict: {
                'exposed_secrets': [시크릿 리스트],
                'exploit_available': True/False
            }
        """
        exposed_secrets = []

        # 방법 1: 페이지가 열려있으면 직접 수집
        if self.page:
            try:
                print("[+] 노출된 시크릿 검색 중 (ExploitInfoCollector)...")

                secrets = self.page.evaluate("""
                    () => {
                        const secrets = [];
                        const patterns = {
                            'api_key': /(?:api[_-]?key|apikey)\\s*[:=]\\s*['"]([a-zA-Z0-9_\\-]{20,})['"])/gi,
                            'jwt': /(eyJ[a-zA-Z0-9_-]+\\.eyJ[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+)/g,
                            'bearer_token': /(?:bearer|token)\\s*[:=]\\s*['"]([a-zA-Z0-9_\\-\\.]{20,})['"])/gi,
                            'aws_key': /(AKIA[0-9A-Z]{16})/g,
                            'github_token': /(ghp_[a-zA-Z0-9]{36})/g,
                            'google_api': /(AIza[0-9A-Za-z\\-_]{35})/g
                        };

                        // 1. HTML 소스코드 전체 검색
                        const htmlSource = document.documentElement.outerHTML;

                        for (const [type, pattern] of Object.entries(patterns)) {
                            const matches = htmlSource.matchAll(pattern);
                            for (const match of matches) {
                                secrets.push({
                                    type: type,
                                    value: match[1] || match[0],
                                    location: 'html_source',
                                    context: match[0].substring(0, 100)
                                });
                            }
                        }

                        // 2. localStorage 검색
                        try {
                            for (let i = 0; i < localStorage.length; i++) {
                                const key = localStorage.key(i);
                                const value = localStorage.getItem(key);

                                if (value && value.length > 20) {
                                    // JWT 패턴 체크
                                    if (value.match(/^eyJ[a-zA-Z0-9_-]+\\./)) {
                                        secrets.push({
                                            type: 'jwt_in_localstorage',
                                            value: value,
                                            location: 'localStorage',
                                            context: `Key: ${key}`
                                        });
                                    }

                                    // API 키 패턴 체크
                                    if (key.toLowerCase().includes('api') || key.toLowerCase().includes('key') || key.toLowerCase().includes('token')) {
                                        secrets.push({
                                            type: 'token_in_localstorage',
                                            value: value,
                                            location: 'localStorage',
                                            context: `Key: ${key}`
                                        });
                                    }
                                }
                            }
                        } catch (e) {}

                        // 3. sessionStorage 검색
                        try {
                            for (let i = 0; i < sessionStorage.length; i++) {
                                const key = sessionStorage.key(i);
                                const value = sessionStorage.getItem(key);

                                if (value && value.length > 20) {
                                    if (value.match(/^eyJ[a-zA-Z0-9_-]+\\./)) {
                                        secrets.push({
                                            type: 'jwt_in_sessionstorage',
                                            value: value,
                                            location: 'sessionStorage',
                                            context: `Key: ${key}`
                                        });
                                    }

                                    if (key.toLowerCase().includes('api') || key.toLowerCase().includes('key') || key.toLowerCase().includes('token')) {
                                        secrets.push({
                                            type: 'token_in_sessionstorage',
                                            value: value,
                                            location: 'sessionStorage',
                                            context: `Key: ${key}`
                                        });
                                    }
                                }
                            }
                        } catch (e) {}

                        return secrets;
                    }
                """)

                exposed_secrets = secrets

                if exposed_secrets and len(exposed_secrets) > 0:
                    print(f"  → [경고] {len(exposed_secrets)}개 노출된 시크릿 발견!")
                    for secret in exposed_secrets[:3]:  # 최대 3개만 출력
                        secret_type = safe_text(secret['type'])
                        location = safe_text(secret['location'])
                        print(f"    - {secret_type} in {location}")
                else:
                    print(f"  → [OK] 노출된 시크릿 없음")

            except Exception as e:
                print(f"  [!] 시크릿 검색 실패: {str(e)}")

        # 방법 2: 페이지가 없으면 저장된 데이터에서 가져오기
        else:
            for report in self.result.security_reports:
                if normalize_url(report.url) == normalize_url(url):
                    exposed_secrets = report.exposed_secrets
                    break

        return {
            'exposed_secrets': exposed_secrets,
            'exploit_available': len(exposed_secrets) > 0
        }

    def get_sensitive_data_info(self, url: str) -> dict:
        """
        2. 민감정보 탈취 익스플로잇 정보
        민감정보가 입력될 수 있는 필드 찾기 (신용카드, SSN, 계좌번호 등 입력 필드)

        폼 필드의 type, name, pattern, maxlength 속성을 분석하여 민감정보 필드 탐지
        """
        sensitive_fields = []

        # 모든 폼을 순회하면서 민감정보 필드 찾기
        for form in self.result.forms:
            # URL이 일치하는 폼만 검사
            if normalize_url(form.action) == normalize_url(url):
                for field in form.fields:
                    # InputField.detect_sensitive_type() 호출
                    sensitive_type = field.detect_sensitive_type()

                    if sensitive_type:
                        # 민감정보 필드 발견!
                        sensitive_fields.append({
                            'field_type': sensitive_type,  # 'credit_card', 'password', 'ssn' 등
                            'field_name': field.name,
                            'input_type': field.input_type,
                            'form_action': form.action,
                            'selector': f"input[name='{field.name}']",
                            'exploit_note': f"{sensitive_type} 입력 필드 - 키로거/민감정보 탈취 가능"
                        })

        return {
            'sensitive_input_fields': sensitive_fields,
            'exploit_available': len(sensitive_fields) > 0
        }

    def get_keylogger_info(self, url: str) -> dict:
        """
        3. 키로거 익스플로잇 정보
        password, text, email 필드 찾기 (입력값 탈취 타겟)
        """
        keylogger_targets = []

        for form in self.result.forms:
            if normalize_url(form.action) == normalize_url(url):
                for field in form.fields:
                    if field.input_type in ['password', 'text', 'email']:
                        keylogger_targets.append({
                            'name': field.name,
                            'type': field.input_type,
                            'form_id': form.form_id,
                            'form_action': form.action,
                            'selector': f"input[name='{field.name}']",
                            'exploit_note': f"키로거로 {field.name} 입력값 탈취 가능"
                        })

        return {
            'targets': keylogger_targets,
            'exploit_available': len(keylogger_targets) > 0
        }

    def get_phishing_info(self, url: str) -> dict:
        """
        4. 피싱 익스플로잇 정보 (심플 버전)

        크롤러 역할:
        - 로그인/회원가입 폼 구조 수집
        - 기본 메타 정보 (타이틀, 로고 유무)
        - URL 전달

        익스플로잇 모듈 역할:
        - target_url로 다시 방문
        - 상세 브랜딩/CSS/이미지 수집
        - 복제 페이지 생성
        """
        cloneable_forms = []

        # 해당 URL의 폼 중 로그인/회원가입 관련 폼 찾기
        for form in self.result.forms:
            if normalize_url(form.action) == normalize_url(url):
                # 로그인/회원가입 폼 판별
                has_username = any(f.name.lower() in ['username', 'user', 'email', 'id'] for f in form.fields)
                has_password = any(f.input_type == 'password' for f in form.fields)

                if has_username or has_password:
                    # 기본 폼 구조만 수집
                    form_info = {
                        'form_id': form.form_id,
                        'action': form.action,
                        'method': form.method,
                        'fields': [],
                        'submit_button_text': None,
                        'is_login_form': has_username and has_password
                    }

                    for field in form.fields:
                        # 필수 정보만
                        field_info = {
                            'name': field.name,
                            'type': field.input_type,
                            'required': field.required
                        }

                        # placeholder도 있으면 추가 (간단한 것만)
                        if field.value and field.input_type in ['text', 'email']:
                            field_info['placeholder'] = field.value

                        # Submit 버튼 텍스트
                        if field.input_type == 'submit':
                            form_info['submit_button_text'] = field.value or 'Login'

                        form_info['fields'].append(field_info)

                    cloneable_forms.append(form_info)

        # 간단한 메타 정보 (보안 리포트에서 가져오기)
        page_title = ""
        has_logo = False

        for report in self.result.security_reports:
            if normalize_url(report.url) == normalize_url(url):
                # 크롤링 시점에 수집한 기본 정보 사용
                page_title = getattr(report, 'page_title', '')
                has_logo = getattr(report, 'has_logo', False)
                break

        return {
            'cloneable_forms': cloneable_forms,
            'target_url': url,                      # ← 익스플로잇 모듈이 다시 방문할 URL
            'page_title': page_title,               # 간단한 참고 정보
            'has_logo': has_logo,                   # 로고 유무
            'exploit_available': len(cloneable_forms) > 0,
            'note': 'Exploit module should visit target_url for detailed phishing page cloning'
        }

    def get_permission_info(self, url: str) -> dict:
        """
        5. 권한 악용 익스플로잇 정보
        외부 JS 파일을 다운로드하여 브라우저 API 사용 패턴 분석

        분석 대상:
        - 외부 JS 파일 (script src="...")
        - 권한 관련 API (geolocation, camera, clipboard 등)
        """
        external_scripts = []
        granted_permissions = []
        downloaded_js_count = 0
        failed_downloads = 0

        if self.page:
            try:
                print("[+] JavaScript API 사용 분석 중 (외부 JS 파일 다운로드)...")

                # 1. 외부 JS 파일 URL 수집
                script_urls = self.page.evaluate("""
                    () => {
                        return Array.from(document.querySelectorAll('script[src]'))
                                    .map(s => s.src)
                                    .filter(src => src && src.trim() !== '');
                    }
                """)

                if not script_urls:
                    print("  → [JS 파일] 외부 스크립트 없음")
                    return {
                        'external_scripts': [],
                        'permission_apis': [],
                        'exploit_available': False,
                        'exploit_note': '외부 JS 파일 없음'
                    }

                print(f"  → [JS 파일] {len(script_urls)}개 발견, 다운로드 중...")

                # 2. 각 JS 파일을 브라우저에서 직접 열어서 내용 수집
                all_js_code = []
                original_url = self.page.url  # 현재 페이지 URL 저장

                for idx, script_url in enumerate(script_urls):
                    try:
                        # Playwright로 JS 파일을 브라우저에서 직접 열기 (세션 유지)
                        self.page.goto(script_url, wait_until='domcontentloaded', timeout=5000)

                        # 브라우저가 렌더링한 JS 내용 읽기
                        js_content = self.page.content()

                        # HTML 태그 제거 (순수 JS만 추출)
                        js_content = self.page.evaluate("""
                            () => {
                                return document.body ? document.body.innerText : document.documentElement.innerText;
                            }
                        """)

                        if js_content and js_content.strip():
                            all_js_code.append(js_content)
                            external_scripts.append(script_url)
                            downloaded_js_count += 1

                            # 다운로드 상태 출력 (처음 5개만)
                            if idx < 5:
                                file_size = len(js_content)
                                file_size_kb = file_size / 1024
                                print(f"    [{idx+1}] ✓ {script_url[:60]}... ({file_size_kb:.1f}KB)")
                        else:
                            failed_downloads += 1

                    except Exception as e:
                        failed_downloads += 1
                        if idx < 3:  # 처음 3개 실패만 출력
                            print(f"    [X] {script_url[:60]}... (로드 실패: {str(e)[:30]})")

                if downloaded_js_count == 0:
                    print("  → [경고] 모든 JS 파일 다운로드 실패")
                    return {
                        'external_scripts': external_scripts,
                        'permission_apis': [],
                        'exploit_available': False,
                        'exploit_note': 'JS 파일 다운로드 실패'
                    }

                print(f"  → [다운로드 완료] {downloaded_js_count}개 성공, {failed_downloads}개 실패")

                # 3. 모든 JS 코드 통합
                combined_js_code = '\n'.join(all_js_code)

                # 4. 권한 관련 API 패턴 매칭
                import re

                permission_patterns = {
                    'geolocation': r'navigator\.geolocation',
                    'notifications': r'Notification\.requestPermission|new\s+Notification',
                    'camera_microphone': r'getUserMedia|mediaDevices',
                    'clipboard': r'navigator\.clipboard'
                }

                for perm_name, pattern in permission_patterns.items():
                    matches = re.findall(pattern, combined_js_code, re.IGNORECASE)
                    if matches:
                        granted_permissions.append({
                            'permission': perm_name,
                            'detected_in_code': True,
                            'occurrences': len(matches),
                            'samples': list(set(matches))[:3],  # 중복 제거 후 최대 3개
                            'note': 'XSS 페이로드로 이 권한을 악용할 수 있음 (피해자가 허용한 경우)'
                        })

                # 5. 결과 출력
                if granted_permissions:
                    print(f"  → [권한 API] {len(granted_permissions)}개 발견")
                    for perm in granted_permissions:
                        perm_name = safe_text(perm['permission'])
                        count = perm.get('occurrences', 0)
                        print(f"    - {perm_name}: {count}회 사용 → XSS 페이로드로 악용 가능")
                else:
                    print(f"  → [권한 API] 권한 관련 API 사용 안 함")

                # JS 파일 확인 후 원래 페이지로 돌아가기
                try:
                    self.page.goto(original_url, wait_until='domcontentloaded', timeout=5000)
                    print(f"  → [복귀] 원래 페이지로 돌아감")
                except Exception:
                    pass

            except Exception as e:
                print(f"  [!] JavaScript API 분석 실패: {str(e)}")

        return {
            'external_scripts': external_scripts,
            'downloaded_js_count': downloaded_js_count,
            'failed_downloads': failed_downloads,
            'permission_apis': granted_permissions,
            'exploit_available': len(granted_permissions) > 0,
            'exploit_note': f'{len(granted_permissions)}개 권한 API 감지 - XSS 페이로드로 악용 가능 (사용자가 권한 허용한 경우)' if granted_permissions else ''
        }

# ========================================
# 퍼저 타겟 JSON 빌더 클래스
# ========================================

class FuzzerTargetBuilder:
    """
    친구의 익스플로잇 모듈이 사용할 JSON 생성

    xss_fuzzer_targets.json 파일 생성:
    - testing: XSS 주입 포인트 (폼, 파라미터)
    - exploits: 5가지 익스플로잇 정보
    - metadata: 보안 분석
    """

    def __init__(self, crawl_result: CrawlResult):
        """
        Args:
            crawl_result: 크롤링 결과 데이터
        """
        self.result = crawl_result
        self.exploit_collector = ExploitInfoCollector(crawl_result)

    def build(self) -> dict:
        """
        xss_fuzzer_targets.json 데이터 생성

        Returns:
            dict: 퍼저 타겟 JSON 데이터
        """
        # 페이지별로 그룹화
        targets_dict = self._group_targets_by_page()

        # JSON 구조 생성
        return {
            'metadata': {
                'target': self.result.base_url,
                'scan_time': self.result.start_time,
                'end_time': self.result.end_time,
                'total_targets': len(targets_dict),
                'total_injection_points': len(self.result.injection_points)
            },
            'targets': list(targets_dict.values()),
            'session': self._get_session_info()
        }

    def save(self, filepath: str = "xss_fuzzer_targets.json"):
        """
        JSON 파일로 저장

        Args:
            filepath: 저장할 파일 경로
        """
        data = self.build()

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"[+] 퍼저 타겟 저장: {filepath}")
        print(f"    - 타겟 페이지: {len(data['targets'])}개")
        print(f"    - 테스트 포인트: {data['metadata']['total_injection_points']}개")

    def _group_targets_by_page(self) -> dict:
        """
        퍼저 타겟을 페이지별로 그룹화
        testing (퍼저용) / exploits (익스플로잇용) / metadata (공통) 분리

        Returns:
            dict: URL별로 그룹화된 타겟
        """
        targets = {}

        # 1. 폼 필드를 URL별로 그룹화 (injectable 필드만)
        for form in self.result.forms:
            # injectable한 필드가 있는지 확인
            injectable_fields = [f for f in form.fields if f.is_injectable()]

            if not injectable_fields:
                continue  # injectable 필드가 없으면 스킵

            url = normalize_url(form.action)

            if url not in targets:
                targets[url] = {
                    'url': form.action,

                    # 퍼저 전용: XSS 주입 포인트 (플랫 구조)
                    'testing': {
                        'injection_points': []
                    },

                    # 익스플로잇 모듈 전용: 7가지 익스플로잇 정보
                    'exploits': self.exploit_collector.collect_all(form.action),

                    # 공통 메타데이터: 보안 분석
                    'metadata': {
                        'security': self._get_security_info(form.action)
                    }
                }

            # submit 버튼 selector 찾기
            submit_selector = self._get_submit_selector(form)

            # 각 injectable 필드를 개별 주입 포인트로 추가
            for field in injectable_fields:
                injection_point = {
                    'type': 'form_field',
                    'page_url': form.source_url,  # 폼이 발견된 실제 페이지 URL
                    'field_name': field.name,
                    'field_type': field.input_type,
                    'field_selector': self._get_field_selector(field),
                    'submit_selector': submit_selector
                }

                # 필드 타입별 추가 정보
                if field.input_type in ['select', 'select-one', 'select-multiple']:
                    # 드롭다운: options 추가
                    if field.options:
                        injection_point['options'] = field.options
                        injection_point['selected_value'] = field.selected_value or (field.options[0] if field.options else None)

                elif field.input_type == 'hidden':
                    # Hidden 필드: 원본 값 추가 (CSRF 토큰 등)
                    if field.value:
                        injection_point['original_value'] = field.value

                elif field.input_type == 'radio':
                    # Radio: options 추가
                    if field.options:
                        injection_point['options'] = field.options

                targets[url]['testing']['injection_points'].append(injection_point)

        # 2. URL 파라미터 그룹화 (Reflected XSS용)
        for injection_point in self.result.injection_points:
            if injection_point.point_type == 'url_param':
                url = normalize_url(injection_point.url)

                if url not in targets:
                    targets[url] = {
                        'url': injection_point.url,

                        # 퍼저 전용: XSS 주입 포인트
                        'testing': {
                            'injection_points': []
                        },

                        # 익스플로잇 모듈 전용: 7가지 익스플로잇 정보
                        'exploits': self.exploit_collector.collect_all(injection_point.url),

                        # 공통 메타데이터: 보안 분석
                        'metadata': {
                            'security': self._get_security_info(injection_point.url)
                        }
                    }

                # URL 파라미터 추가
                targets[url]['testing']['injection_points'].append({
                    'type': 'url_param',
                    'url': injection_point.url,
                    'param_name': injection_point.parameter_name,
                    'param_value': injection_point.test_value,  # 현재 값
                    'method': injection_point.method
                })

        return targets

    def _get_submit_selector(self, form: FormInfo) -> str:
        """
        폼의 submit 버튼 selector 생성

        Args:
            form: FormInfo 객체

        Returns:
            str: submit 버튼의 CSS selector
        """
        # submit 타입 필드 찾기
        for field in form.fields:
            if field.input_type == 'submit':
                if field.name:
                    return f"input[name='{field.name}']"
                else:
                    return "input[type='submit']"

        # submit 버튼 없으면 기본값
        if form.form_id:
            return f"#{form.form_id} button[type='submit'], #{form.form_id} input[type='submit']"
        else:
            return "button[type='submit'], input[type='submit']"

    def _get_field_selector(self, field: InputField) -> str:
        """
        필드의 CSS selector 생성

        Args:
            field: InputField 객체

        Returns:
            str: 필드의 CSS selector
        """
        if field.input_type in ['select', 'select-one', 'select-multiple']:
            return f"select[name='{field.name}']"
        elif field.input_type == 'textarea':
            return f"textarea[name='{field.name}']"
        else:
            return f"input[name='{field.name}']"

    def _get_security_info(self, url: str) -> dict:
        """
        특정 URL의 보안 정보 가져오기

        Args:
            url: 타겟 URL

        Returns:
            dict: 보안 정보
        """
        for report in self.result.security_reports:
            if normalize_url(report.url) == normalize_url(url):
                return {
                    'has_csp': report.csp is not None,
                    'csp_directive': report.csp if report.csp else None,
                    'has_vulnerable_cookies': len(report.js_accessible_cookies) > 0
                }

        return {
            'has_csp': False,
            'csp_directive': None,
            'has_vulnerable_cookies': False
        }

    def _get_session_info(self) -> dict:
        """
        세션 정보 추출

        Returns:
            dict: 세션/쿠키 정보
        """
        # 첫 번째 보안 리포트에서 쿠키 정보 가져오기
        if self.result.security_reports:
            cookies = []
            for cookie in self.result.security_reports[0].cookies:
                cookies.append({
                    'name': cookie['name'],
                    'domain': cookie.get('domain', ''),
                    'http_only': cookie.get('httpOnly', False),
                    'secure': cookie.get('secure', False)
                })

            return {
                'cookies': cookies,
                'requires_login': True  # 크롤러가 로그인 했다면
            }

        return {
            'cookies': [],
            'requires_login': False
        }


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
    - POST 파라미터 상세 분석    - 엔드포인트 중복 체크    """

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
        self.endpoint_keys: Set[str] = set()
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

        # 중복 체크
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

        # POST 파라미터 상세 분석
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
        POST 요청에서 파라미터 상세 추출
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
    - 폼 자동 제출    - 인터랙티브 요소 자동 클릭    """

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
                enctype=form_data['enctype'],
                source_url=self.page.url  # 폼이 발견된 실제 페이지 URL
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
    # 폼 자동 제출    
    # ========================================

    def submit_forms_with_test_data(self, forms: List[FormInfo]) -> Dict:
        """
        발견한 폼들에 테스트 데이터를 채워서 실제로 제출
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
    # 인터랙티브 요소 자동 클릭    
    # ========================================

    def trigger_interactive_elements(self) -> Dict:
        """
        발견한 모든 인터랙티브 요소를 자동으로 클릭
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
# 보안 분석 클래스
# ========================================

class SecurityAnalyzer:
    """
    보안 설정 분석 기능

    주요 기능:
    - CSP (Content Security Policy) 분석
    - 보안 헤더 검사
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

        # 각 보안 항목별 분석 실행
        self._analyze_csp(security_info, response_headers)
        self._analyze_security_headers(security_info, response_headers)

        return security_info

    # ========================================
    # CSP 분석
    # ========================================

    def _analyze_csp(self, security_info: SecurityInfo, response_headers: Optional[Dict[str, str]]):
        """CSP(Content Security Policy) 분석"""
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

        # CSP 분석 및 취약점 확인
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

    # ========================================
    # 보안 헤더 분석
    # ========================================

    def _analyze_security_headers(self, security_info: SecurityInfo, response_headers: Optional[Dict[str, str]]):
        """보안 헤더 분석"""
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
    - 폼 자동 제출    - 인터랙티브 요소 자동 클릭    - 크롤링 결과 JSON 저장
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

        # 폼 자동 제출        if self.config.submit_forms and forms:
            dom.submit_forms_with_test_data(forms)

        # 인터랙티브 요소 자동 클릭        if self.config.trigger_elements:
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

        # XSS 익스플로잇 정보 수집 (ExploitInfoCollector가 직접 페이지에서 수집)
        exploit_collector = ExploitInfoCollector(self.result, self.browser.page, self.browser.context)

        # 쿠키 종합 분석 (JS 접근 가능 쿠키 + 보안 속성)
        cookie_info = exploit_collector.get_cookie_theft_info(url)
        security_report.js_accessible_cookies = cookie_info['stealable_cookies']
        security_report.cookies = cookie_info['all_cookies']  # 쿠키 보안 속성 저장

        # 노출된 시크릿 수집
        secrets_info = exploit_collector.get_exposed_secrets_info(url)
        security_report.exposed_secrets = secrets_info['exposed_secrets']

        self.result.add_security_report(security_report)

        return True

    def _print_summary(self):
        """크롤링 결과 요약 출력"""
        print(f"\n{'='*60}")
        print(f"크롤링 완료!")
        print(f"{'='*60}")
        print(f"방문한 페이지: {len(self.result.crawled_urls)}개")
        print(f"발견한 폼: {len(self.result.forms)}개")
        print(f"테스트 포인트: {len(self.result.injection_points)}개")
        print(f"{'='*60}\n")


# ========================================
# 사용 예시
# ========================================

if __name__ == "__main__":
    # 크롤러 설정
    config = CrawlerConfig(
        headless=False,                # 브라우저 표시
        max_depth=2,                   # 최대 2단계까지 크롤링
        max_pages=50,                  # 최대 50페이지
        timeout=10000,                 # 10초 타임아웃

        # 동적 콘텐츠 처리
        handle_infinite_scroll=True,   # 무한 스크롤 처리
        max_scrolls=3,                 # 최대 3회 스크롤
        handle_load_more=True,         # 더보기 버튼 처리
        max_load_more_clicks=3,        # 최대 3회 클릭

        # 폼 자동 제출
        submit_forms=True,            # 폼 자동 제출 (위험할 수 있음!)
        max_form_submissions=3,        # 최대 3개 폼만 제출

        # 인터랙티브 요소 자동 클릭
        trigger_elements=True,        # 요소 자동 클릭 (위험할 수 있음!)
        max_element_clicks=5,          # 최대 5개 요소만 클릭

        # # 로그인이 필요한 경우
        # login_url="http://192.168.204.128/dvwa/login.php",
        # username="admin",
        # password="password"
    )

    # 크롤러 생성 및 실행
    crawler = XSSCrawler(config)
    result = crawler.crawl("https://0a40001504721fd580e8269700280056.web-security-academy.net/")

    # 결과 저장
    print("\n" + "="*60)
    print("결과 저장 중...")
    print("="*60)

    # 퍼저 타겟 JSON 생성 및 저장 (친구 익스플로잇 모듈용)
    builder = FuzzerTargetBuilder(result)
    builder.save("xss_fuzzer_targets.json")

    print("="*60)
