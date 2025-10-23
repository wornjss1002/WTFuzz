"""
Context Analyzer - 마커 기반 컨텍스트 분석 모듈

XSS 퍼징을 위해 각 인젝션 포인트에 마커를 주입하고,
응답에서 마커가 어디에 반사되는지 분석하여 컨텍스트를 파악합니다.

핵심 기능:
1. 고유 마커 생성
2. 인젝션 포인트별 마커 주입
3. HTML 응답 분석 (BeautifulSoup)
4. 컨텍스트 분류 (HTML body, JS, Attribute, URL, Comment 등)
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from urllib.parse import urlencode, quote
import secrets
import re
from bs4 import BeautifulSoup
from playwright.sync_api import Page, Response


# ========================================
# 데이터 클래스
# ========================================

@dataclass
class ReflectionContext:
    """마커가 반사된 컨텍스트 정보"""
    context_type: str                    # 컨텍스트 타입
    location: str                        # 구체적 위치 (코드 스니펫)
    line_number: Optional[int] = None    # HTML 라인 번호
    tag_name: Optional[str] = None       # HTML 태그 이름
    attribute_name: Optional[str] = None # 속성 이름 (속성 컨텍스트일 경우)
    surrounding_code: str = ""           # 주변 코드 (전후 50자)

    def to_dict(self) -> dict:
        """딕셔너리로 변환"""
        return {
            'context_type': self.context_type,
            'location': self.location,
            'line_number': self.line_number,
            'tag_name': self.tag_name,
            'attribute_name': self.attribute_name,
            'surrounding_code': self.surrounding_code
        }


@dataclass
class AnalysisResult:
    """컨텍스트 분석 결과"""
    url: str
    parameter: str
    method: str                         # GET, POST
    marker: str                         # 사용한 마커
    reflected: bool                     # 반사 여부
    contexts: List[ReflectionContext] = field(default_factory=list)
    response_length: int = 0
    response_time_ms: float = 0.0

    def to_dict(self) -> dict:
        """딕셔너리로 변환"""
        return {
            'url': self.url,
            'parameter': self.parameter,
            'method': self.method,
            'marker': self.marker,
            'reflected': self.reflected,
            'contexts': [ctx.to_dict() for ctx in self.contexts],
            'response_length': self.response_length,
            'response_time_ms': self.response_time_ms
        }


# ========================================
# 컨텍스트 분석기
# ========================================

class ContextAnalyzer:
    """
    마커 기반 컨텍스트 분석기

    각 인젝션 포인트에 고유 마커를 주입하고,
    응답 HTML을 분석하여 마커가 반사된 컨텍스트를 식별합니다.
    """

    # 컨텍스트 타입 상수
    CONTEXT_HTML_BODY = "html_body"           # HTML 본문
    CONTEXT_HTML_ATTRIBUTE = "html_attribute" # HTML 속성
    CONTEXT_JAVASCRIPT = "javascript"         # JavaScript 코드
    CONTEXT_JAVASCRIPT_STRING = "js_string"   # JS 문자열 내부
    CONTEXT_URL = "url"                       # URL 내부
    CONTEXT_COMMENT = "comment"               # 주석 내부
    CONTEXT_STYLE = "style"                   # CSS/Style
    CONTEXT_UNKNOWN = "unknown"               # 알 수 없음

    def __init__(self, page: Page):
        """
        Args:
            page: Playwright Page 객체
        """
        self.page = page
        self.marker_prefix = "XSSTEST_"

    def generate_marker(self) -> str:
        """
        고유한 마커 생성

        Returns:
            str: 랜덤 마커 (예: XSSTEST_a1b2c3d4)
        """
        random_suffix = secrets.token_hex(4)  # 8자 16진수
        return f"{self.marker_prefix}{random_suffix}"

    def analyze_injection_point(
        self,
        url: str,
        param_name: str,
        method: str = "GET",
        additional_params: Dict[str, str] = None
    ) -> AnalysisResult:
        """
        인젝션 포인트 분석

        Args:
            url: 테스트할 URL
            param_name: 테스트할 파라미터 이름
            method: HTTP 메서드 (GET 또는 POST)
            additional_params: 추가 파라미터 (다른 필드의 기본값 등)

        Returns:
            AnalysisResult: 분석 결과
        """
        marker = self.generate_marker()
        params = additional_params.copy() if additional_params else {}
        params[param_name] = marker

        # 요청 전송
        import time
        start_time = time.time()

        if method.upper() == "GET":
            test_url = f"{url}?{urlencode(params)}"
            response = self.page.goto(test_url, wait_until='networkidle', timeout=30000)
        else:  # POST
            # POST 요청은 Playwright의 route를 사용하거나 별도 처리 필요
            # 현재는 간단한 구현으로 진행
            response = self._send_post_request(url, params)

        response_time_ms = (time.time() - start_time) * 1000

        # 응답 HTML 가져오기
        html_content = self.page.content()
        response_length = len(html_content)

        # 마커 반사 여부 확인
        reflected = marker in html_content

        # 컨텍스트 분석
        contexts = []
        if reflected:
            contexts = self._analyze_contexts(html_content, marker)

        return AnalysisResult(
            url=url,
            parameter=param_name,
            method=method,
            marker=marker,
            reflected=reflected,
            contexts=contexts,
            response_length=response_length,
            response_time_ms=response_time_ms
        )

    def _send_post_request(self, url: str, params: Dict[str, str]) -> Optional[Response]:
        """
        POST 요청 전송 (간단한 구현)

        Args:
            url: URL
            params: POST 파라미터

        Returns:
            Response 객체
        """
        # Playwright로 폼 제출 시뮬레이션
        # 실제 구현에서는 더 정교하게 처리 필요
        self.page.goto(url, wait_until='networkidle')

        # 폼 찾아서 제출
        # 이 부분은 실제 페이지 구조에 따라 달라질 수 있음
        return None

    def _analyze_contexts(self, html: str, marker: str) -> List[ReflectionContext]:
        """
        HTML 컨텐츠를 분석하여 마커가 반사된 모든 컨텍스트 찾기

        Args:
            html: HTML 컨텐츠
            marker: 찾을 마커

        Returns:
            List[ReflectionContext]: 발견된 컨텍스트 목록
        """
        contexts = []
        soup = BeautifulSoup(html, 'html.parser')

        # 1. HTML 본문 텍스트에서 마커 찾기
        contexts.extend(self._find_in_html_body(soup, marker))

        # 2. HTML 속성에서 마커 찾기
        contexts.extend(self._find_in_attributes(soup, marker))

        # 3. JavaScript 코드에서 마커 찾기
        contexts.extend(self._find_in_javascript(soup, marker, html))

        # 4. 주석에서 마커 찾기
        contexts.extend(self._find_in_comments(soup, marker))

        # 5. Style에서 마커 찾기
        contexts.extend(self._find_in_style(soup, marker))

        # 6. URL에서 마커 찾기
        contexts.extend(self._find_in_urls(soup, marker))

        return contexts

    def _find_in_html_body(self, soup: BeautifulSoup, marker: str) -> List[ReflectionContext]:
        """HTML 본문 텍스트에서 마커 찾기"""
        contexts = []

        # 모든 텍스트 노드에서 마커 검색
        for element in soup.find_all(text=re.compile(re.escape(marker))):
            parent = element.parent

            # 스크립트나 스타일 태그 내부는 제외 (별도 처리)
            if parent.name in ['script', 'style']:
                continue

            context = ReflectionContext(
                context_type=self.CONTEXT_HTML_BODY,
                location=str(element)[:200],  # 최대 200자
                tag_name=parent.name,
                surrounding_code=self._get_surrounding_code(str(parent), marker)
            )
            contexts.append(context)

        return contexts

    def _find_in_attributes(self, soup: BeautifulSoup, marker: str) -> List[ReflectionContext]:
        """HTML 속성에서 마커 찾기"""
        contexts = []

        for tag in soup.find_all(True):  # 모든 태그
            for attr_name, attr_value in tag.attrs.items():
                # 속성 값이 문자열이고 마커를 포함하는 경우
                if isinstance(attr_value, str) and marker in attr_value:
                    context = ReflectionContext(
                        context_type=self.CONTEXT_HTML_ATTRIBUTE,
                        location=f'<{tag.name} {attr_name}="{attr_value[:100]}">',
                        tag_name=tag.name,
                        attribute_name=attr_name,
                        surrounding_code=str(tag)[:200]
                    )
                    contexts.append(context)

                # 리스트 형태의 속성 값 (class 등)
                elif isinstance(attr_value, list):
                    for val in attr_value:
                        if marker in str(val):
                            context = ReflectionContext(
                                context_type=self.CONTEXT_HTML_ATTRIBUTE,
                                location=f'<{tag.name} {attr_name}="{val}">',
                                tag_name=tag.name,
                                attribute_name=attr_name,
                                surrounding_code=str(tag)[:200]
                            )
                            contexts.append(context)

        return contexts

    def _find_in_javascript(
        self,
        soup: BeautifulSoup,
        marker: str,
        html: str
    ) -> List[ReflectionContext]:
        """JavaScript 코드에서 마커 찾기"""
        contexts = []

        # <script> 태그 내부
        for script in soup.find_all('script'):
            script_content = script.string
            if script_content and marker in script_content:
                # JavaScript 문자열 내부인지 확인
                if self._is_in_js_string(script_content, marker):
                    context_type = self.CONTEXT_JAVASCRIPT_STRING
                else:
                    context_type = self.CONTEXT_JAVASCRIPT

                context = ReflectionContext(
                    context_type=context_type,
                    location=script_content[:200],
                    tag_name='script',
                    surrounding_code=self._get_surrounding_code(script_content, marker)
                )
                contexts.append(context)

        # 인라인 이벤트 핸들러 (onclick, onerror 등)
        for tag in soup.find_all(True):
            for attr_name, attr_value in tag.attrs.items():
                if attr_name.startswith('on') and isinstance(attr_value, str):
                    if marker in attr_value:
                        context = ReflectionContext(
                            context_type=self.CONTEXT_JAVASCRIPT,
                            location=f'{attr_name}="{attr_value[:100]}"',
                            tag_name=tag.name,
                            attribute_name=attr_name,
                            surrounding_code=attr_value[:200]
                        )
                        contexts.append(context)

        return contexts

    def _find_in_comments(self, soup: BeautifulSoup, marker: str) -> List[ReflectionContext]:
        """HTML 주석에서 마커 찾기"""
        contexts = []

        from bs4 import Comment
        for comment in soup.find_all(text=lambda t: isinstance(t, Comment)):
            if marker in comment:
                context = ReflectionContext(
                    context_type=self.CONTEXT_COMMENT,
                    location=f'<!-- {str(comment)[:100]} -->',
                    surrounding_code=str(comment)[:200]
                )
                contexts.append(context)

        return contexts

    def _find_in_style(self, soup: BeautifulSoup, marker: str) -> List[ReflectionContext]:
        """Style 태그 및 속성에서 마커 찾기"""
        contexts = []

        # <style> 태그
        for style in soup.find_all('style'):
            if style.string and marker in style.string:
                context = ReflectionContext(
                    context_type=self.CONTEXT_STYLE,
                    location=style.string[:200],
                    tag_name='style',
                    surrounding_code=self._get_surrounding_code(style.string, marker)
                )
                contexts.append(context)

        # style 속성
        for tag in soup.find_all(style=True):
            if marker in tag['style']:
                context = ReflectionContext(
                    context_type=self.CONTEXT_STYLE,
                    location=f'style="{tag["style"][:100]}"',
                    tag_name=tag.name,
                    attribute_name='style',
                    surrounding_code=tag['style'][:200]
                )
                contexts.append(context)

        return contexts

    def _find_in_urls(self, soup: BeautifulSoup, marker: str) -> List[ReflectionContext]:
        """URL에서 마커 찾기 (href, src, action 등)"""
        contexts = []
        url_attributes = ['href', 'src', 'action', 'data', 'formaction']

        for tag in soup.find_all(True):
            for attr in url_attributes:
                if tag.has_attr(attr):
                    url_value = tag[attr]
                    if isinstance(url_value, str) and marker in url_value:
                        context = ReflectionContext(
                            context_type=self.CONTEXT_URL,
                            location=f'{attr}="{url_value[:100]}"',
                            tag_name=tag.name,
                            attribute_name=attr,
                            surrounding_code=url_value[:200]
                        )
                        contexts.append(context)

        return contexts

    def _is_in_js_string(self, js_code: str, marker: str) -> bool:
        """
        JavaScript 코드에서 마커가 문자열 내부에 있는지 확인

        Args:
            js_code: JavaScript 코드
            marker: 마커

        Returns:
            bool: 문자열 내부면 True
        """
        # 간단한 휴리스틱: 마커 앞뒤에 따옴표가 있는지 확인
        # 더 정교한 파싱이 필요하면 esprima 같은 JS 파서 사용
        marker_pos = js_code.find(marker)
        if marker_pos == -1:
            return False

        # 마커 앞의 문자열에서 따옴표 개수 세기
        before = js_code[:marker_pos]
        single_quotes = before.count("'") - before.count("\\'")
        double_quotes = before.count('"') - before.count('\\"')
        backticks = before.count('`') - before.count('\\`')

        # 홀수 개면 문자열 내부
        return (single_quotes % 2 == 1) or (double_quotes % 2 == 1) or (backticks % 2 == 1)

    def _get_surrounding_code(self, text: str, marker: str, context_length: int = 50) -> str:
        """
        마커 주변 코드 추출

        Args:
            text: 전체 텍스트
            marker: 마커
            context_length: 전후로 추출할 길이

        Returns:
            str: 주변 코드
        """
        marker_pos = text.find(marker)
        if marker_pos == -1:
            return ""

        start = max(0, marker_pos - context_length)
        end = min(len(text), marker_pos + len(marker) + context_length)

        surrounding = text[start:end]

        # 앞뒤 생략 표시
        if start > 0:
            surrounding = "..." + surrounding
        if end < len(text):
            surrounding = surrounding + "..."

        return surrounding


# ========================================
# 헬퍼 함수
# ========================================

def print_analysis_result(result: AnalysisResult):
    """분석 결과를 보기 좋게 출력"""
    print(f"\n{'='*60}")
    print(f"URL: {result.url}")
    print(f"Parameter: {result.parameter}")
    print(f"Method: {result.method}")
    print(f"Marker: {result.marker}")
    print(f"Reflected: {'YES' if result.reflected else 'NO'}")
    print(f"Response: {result.response_length} bytes, {result.response_time_ms:.2f}ms")

    if result.contexts:
        print(f"\nContexts found: {len(result.contexts)}")
        for i, ctx in enumerate(result.contexts, 1):
            print(f"\n  [{i}] Type: {ctx.context_type}")
            if ctx.tag_name:
                print(f"      Tag: <{ctx.tag_name}>")
            if ctx.attribute_name:
                print(f"      Attribute: {ctx.attribute_name}")
            print(f"      Location: {ctx.location}")
            if ctx.surrounding_code:
                print(f"      Context: {ctx.surrounding_code}")
    else:
        print("\nNo reflection contexts found.")

    print(f"{'='*60}\n")
