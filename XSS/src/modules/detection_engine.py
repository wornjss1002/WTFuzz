"""
Detection Engine Module
=======================

Playwright 기반 XSS 탐지 엔진
"""

import asyncio
import hashlib
import base64
import sys
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, TYPE_CHECKING
from enum import Enum
from datetime import datetime
from pathlib import Path

# 공통 모델 import
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.models import ConfidenceLevel, DetectionEvidence

if TYPE_CHECKING:
    from playwright.async_api import Browser, Page, BrowserContext

try:
    from playwright.async_api import async_playwright, Browser, Page, BrowserContext
except ImportError:
    print("경고: Playwright가 설치되지 않았습니다. 'pip install playwright'로 설치해주세요.")
    Browser = Any  # type: ignore
    Page = Any  # type: ignore
    BrowserContext = Any  # type: ignore


class DetectionMethod(Enum):
    """탐지 방법 (Detection Engine 전용)"""
    CONSOLE = "console"
    DIALOG = "dialog"
    DOM_MUTATION = "dom_mutation"
    EXECUTION_CONTEXT = "execution_context"
    CSP_VIOLATION = "csp_violation"
    NETWORK_ACTIVITY = "network_activity"


@dataclass
class DetectionResult:
    """탐지 결과"""
    url: str
    payload: str
    detected: bool
    confidence: ConfidenceLevel
    evidence: List[DetectionEvidence] = field(default_factory=list)
    screenshot: Optional[bytes] = None
    dom_snapshot: Optional[str] = None
    response_body: Optional[str] = None
    execution_time: float = 0.0

    def get_triggered_methods(self) -> List[str]:
        """트리거된 탐지 메서드 목록"""
        return [e.method.value for e in self.evidence if e.triggered]

    def calculate_confidence(self) -> ConfidenceLevel:
        """신뢰도 계산"""
        triggered_count = sum(1 for e in self.evidence if e.triggered)

        if triggered_count >= 3:
            return ConfidenceLevel.HIGH
        elif triggered_count == 2:
            return ConfidenceLevel.MEDIUM
        elif triggered_count == 1:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.FALSE

    def to_dict(self) -> Dict:
        return {
            'url': self.url,
            'payload': self.payload,
            'detected': self.detected,
            'confidence': self.confidence.value,
            'triggered_methods': self.get_triggered_methods(),
            'evidence': [e.to_dict() for e in self.evidence],
            'has_screenshot': self.screenshot is not None,
            'execution_time': self.execution_time
        }


class DetectionEngine:
    """
    Playwright 기반 XSS 탐지 엔진

    Features:
    - 다중 탐지 메커니즘
    - 비동기 브라우저 자동화
    - 증거 수집 및 스크린샷
    - False Positive 최소화
    """

    def __init__(
        self,
        headless: bool = True,
        timeout: int = 30000,
        user_agent: Optional[str] = None
    ):
        """
        DetectionEngine 초기화

        Args:
            headless: 헤드리스 모드 사용 여부
            timeout: 페이지 로드 타임아웃 (ms)
            user_agent: 커스텀 User-Agent
        """
        self.headless = headless
        self.timeout = timeout
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )

        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None

    async def initialize(self):
        """브라우저 초기화"""
        playwright = await async_playwright().start()
        self.browser = await playwright.chromium.launch(headless=self.headless)
        self.context = await self.browser.new_context(
            user_agent=self.user_agent,
            viewport={'width': 1920, 'height': 1080}
        )

    async def close(self):
        """브라우저 종료"""
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()

    async def detect_xss(
        self,
        url: str,
        payload: str,
        marker: Optional[str] = None
    ) -> DetectionResult:
        """
        XSS 탐지 메인 메서드

        Args:
            url: 테스트할 URL (페이로드 포함)
            payload: 사용된 페이로드
            marker: 고유 마커 (중복 탐지 방지)

        Returns:
            DetectionResult 객체
        """
        start_time = asyncio.get_event_loop().time()

        if marker is None:
            marker = self._generate_marker(payload)

        # 새 페이지 생성
        page = await self.context.new_page()

        # 탐지 리스너 설정
        evidence = []

        # 1. Console Detection
        console_evidence = await self._setup_console_detection(page)
        evidence.append(console_evidence)

        # 2. Dialog Detection
        dialog_evidence = await self._setup_dialog_detection(page)
        evidence.append(dialog_evidence)

        # 3. CSP Violation Detection
        csp_evidence = await self._setup_csp_detection(page)
        evidence.append(csp_evidence)

        # 4. Network Activity Detection
        network_evidence = await self._setup_network_detection(page, marker)
        evidence.append(network_evidence)

        try:
            # 페이지 로드
            await page.goto(url, timeout=self.timeout, wait_until='networkidle')

            # 잠시 대기 (JavaScript 실행 시간)
            await asyncio.sleep(2)

            # 5. DOM Mutation Detection
            dom_evidence = await self._check_dom_mutation(page, marker)
            evidence.append(dom_evidence)

            # 6. Execution Context Detection
            exec_evidence = await self._check_execution_context(page, marker)
            evidence.append(exec_evidence)

            # 스크린샷 캡처
            screenshot = await page.screenshot(full_page=True)

            # DOM 스냅샷
            dom_snapshot = await page.content()

            # 응답 바디
            response_body = await page.content()

        except Exception as e:
            print(f"페이지 로드 오류: {str(e)}")
            screenshot = None
            dom_snapshot = None
            response_body = None

        finally:
            await page.close()

        # 결과 생성
        end_time = asyncio.get_event_loop().time()
        execution_time = end_time - start_time

        result = DetectionResult(
            url=url,
            payload=payload,
            detected=False,  # 나중에 계산
            confidence=ConfidenceLevel.FALSE,  # 나중에 계산
            evidence=evidence,
            screenshot=screenshot,
            dom_snapshot=dom_snapshot,
            response_body=response_body,
            execution_time=execution_time
        )

        # 탐지 여부 및 신뢰도 계산
        result.confidence = result.calculate_confidence()
        result.detected = result.confidence in [ConfidenceLevel.HIGH, ConfidenceLevel.MEDIUM]

        return result

    async def _setup_console_detection(self, page: Page) -> DetectionEvidence:
        """콘솔 메시지 탐지 설정"""
        console_messages = []

        def on_console(msg):
            console_messages.append({
                'type': msg.type,
                'text': msg.text,
                'location': msg.location
            })

        page.on('console', on_console)

        # 대기 후 확인
        await asyncio.sleep(0.5)

        # XSS 관련 메시지 탐지
        triggered = any(
            'xss' in msg['text'].lower() or
            'alert' in msg['text'].lower() or
            msg['type'] == 'error'
            for msg in console_messages
        )

        return DetectionEvidence(
            method=DetectionMethod.CONSOLE.value,
            triggered=triggered,
            data=console_messages if triggered else None
        )

    async def _setup_dialog_detection(self, page: Page) -> DetectionEvidence:
        """다이얼로그 탐지 설정"""
        dialog_triggered = {'value': False, 'data': None}

        async def on_dialog(dialog):
            dialog_triggered['value'] = True
            dialog_triggered['data'] = {
                'type': dialog.type,
                'message': dialog.message
            }
            await dialog.dismiss()

        page.on('dialog', on_dialog)

        return DetectionEvidence(
            method=DetectionMethod.DIALOG.value,
            triggered=dialog_triggered['value'],
            data=dialog_triggered['data']
        )

    async def _setup_csp_detection(self, page: Page) -> DetectionEvidence:
        """CSP 위반 탐지 설정"""
        csp_violations = []

        def on_page_error(error):
            error_text = str(error)
            if 'Content Security Policy' in error_text or 'CSP' in error_text:
                csp_violations.append(error_text)

        page.on('pageerror', on_page_error)

        await asyncio.sleep(0.5)

        return DetectionEvidence(
            method=DetectionMethod.CSP_VIOLATION.value,
            triggered=len(csp_violations) > 0,
            data=csp_violations if csp_violations else None
        )

    async def _setup_network_detection(self, page: Page, marker: str) -> DetectionEvidence:
        """네트워크 활동 탐지 설정"""
        suspicious_requests = []

        def on_request(request):
            # 마커가 포함된 요청 탐지
            if marker in request.url:
                suspicious_requests.append({
                    'url': request.url,
                    'method': request.method,
                    'headers': dict(request.headers)
                })

        page.on('request', on_request)

        await asyncio.sleep(0.5)

        return DetectionEvidence(
            method=DetectionMethod.NETWORK_ACTIVITY.value,
            triggered=len(suspicious_requests) > 0,
            data=suspicious_requests if suspicious_requests else None
        )

    async def _check_dom_mutation(self, page: Page, marker: str) -> DetectionEvidence:
        """DOM 변형 탐지"""
        try:
            # 마커가 DOM에 주입되었는지 확인
            result = await page.evaluate(f"""
                () => {{
                    const marker = '{marker}';
                    const html = document.documentElement.innerHTML;
                    return html.includes(marker);
                }}
            """)

            return DetectionEvidence(
                method=DetectionMethod.DOM_MUTATION.value,
                triggered=result,
                data={'marker_found': result}
            )
        except Exception as e:
            return DetectionEvidence(
                method=DetectionMethod.DOM_MUTATION.value,
                triggered=False,
                data={'error': str(e)}
            )

    async def _check_execution_context(self, page: Page, marker: str) -> DetectionEvidence:
        """실행 컨텍스트 탐지"""
        try:
            # 전역 변수나 함수가 정의되었는지 확인
            result = await page.evaluate(f"""
                () => {{
                    const marker = 'xss_{marker}';
                    // window 객체에 마커 확인
                    if (window[marker] !== undefined) return true;
                    // alert 함수가 호출되었는지 확인
                    if (window.__xss_detected__) return true;
                    return false;
                }}
            """)

            return DetectionEvidence(
                method=DetectionMethod.EXECUTION_CONTEXT.value,
                triggered=result,
                data={'execution_confirmed': result}
            )
        except Exception as e:
            return DetectionEvidence(
                method=DetectionMethod.EXECUTION_CONTEXT.value,
                triggered=False,
                data={'error': str(e)}
            )

    def _generate_marker(self, payload: str) -> str:
        """페이로드용 고유 마커 생성"""
        hash_obj = hashlib.md5(payload.encode())
        return hash_obj.hexdigest()[:8]

    async def batch_detect(
        self,
        test_cases: List[tuple[str, str]]
    ) -> List[DetectionResult]:
        """
        배치 탐지

        Args:
            test_cases: (URL, 페이로드) 튜플 리스트

        Returns:
            DetectionResult 리스트
        """
        results = []

        for url, payload in test_cases:
            result = await self.detect_xss(url, payload)
            results.append(result)

        return results


# 사용 예제
async def main():
    """테스트 예제"""
    engine = DetectionEngine(headless=True)

    try:
        await engine.initialize()

        # 테스트 케이스
        test_url = "https://example.com/search?q=<script>alert('XSS')</script>"
        payload = "<script>alert('XSS')</script>"

        print(f"테스트 URL: {test_url}")
        print("탐지 시작...")

        result = await engine.detect_xss(test_url, payload)

        print(f"\n=== 탐지 결과 ===")
        print(f"탐지 여부: {result.detected}")
        print(f"신뢰도: {result.confidence.value}")
        print(f"실행 시간: {result.execution_time:.2f}초")
        print(f"트리거된 메서드: {result.get_triggered_methods()}")

        if result.evidence:
            print(f"\n=== 증거 ===")
            for ev in result.evidence:
                if ev.triggered:
                    print(f"- {ev.method.value}: {ev.data}")

    finally:
        await engine.close()


if __name__ == "__main__":
    asyncio.run(main())
