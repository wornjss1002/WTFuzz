"""
XSS Verifier: XSS 페이로드 실행 검증 모듈

실제 브라우저에서 XSS가 실행되는지 검증합니다.
- JavaScript alert/confirm/prompt 감지
- DOM 변화 추적
- 저장형 XSS 검증
- console.log 모니터링
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Callable
from playwright.sync_api import Page, Dialog, ConsoleMessage
import time
import secrets


@dataclass
class XSSEvidence:
    """XSS 실행 증거"""
    evidence_type: str  # 'dialog', 'dom_change', 'console', 'redirect'
    description: str
    timestamp: float
    details: Dict[str, Any]


@dataclass
class VerificationResult:
    """XSS 검증 결과"""
    url: str
    payload: str
    verified: bool  # XSS 실행 확인 여부
    evidences: List[XSSEvidence]
    execution_time: float  # 검증 소요 시간 (초)
    error: Optional[str] = None


class XSSVerifier:
    """
    XSS 실행 검증기

    Playwright를 사용하여 실제 브라우저에서 XSS가 실행되는지 확인합니다.
    """

    def __init__(self, page: Page, timeout: int = 5000):
        """
        Args:
            page: Playwright Page 객체
            timeout: 검증 타임아웃 (밀리초)
        """
        self.page = page
        self.timeout = timeout

        # 증거 수집
        self.evidences: List[XSSEvidence] = []

        # 이벤트 핸들러 등록 상태
        self._handlers_registered = False

    def _register_handlers(self):
        """이벤트 핸들러 등록"""
        if self._handlers_registered:
            return

        # Dialog 이벤트 (alert, confirm, prompt)
        self.page.on('dialog', self._handle_dialog)

        # Console 메시지
        self.page.on('console', self._handle_console)

        # Page error
        self.page.on('pageerror', self._handle_page_error)

        self._handlers_registered = True

    def _unregister_handlers(self):
        """이벤트 핸들러 제거"""
        if not self._handlers_registered:
            return

        try:
            self.page.remove_listener('dialog', self._handle_dialog)
            self.page.remove_listener('console', self._handle_console)
            self.page.remove_listener('pageerror', self._handle_page_error)
        except:
            pass  # 이미 제거된 경우 무시

        self._handlers_registered = False

    def _handle_dialog(self, dialog: Dialog):
        """
        Dialog 이벤트 핸들러 (alert, confirm, prompt)

        XSS의 가장 확실한 증거입니다.
        """
        evidence = XSSEvidence(
            evidence_type='dialog',
            description=f'{dialog.type} dialog detected',
            timestamp=time.time(),
            details={
                'type': dialog.type,  # 'alert', 'confirm', 'prompt', 'beforeunload'
                'message': dialog.message,
                'default_value': dialog.default_value if dialog.type == 'prompt' else None
            }
        )
        self.evidences.append(evidence)

        # Dialog를 자동으로 처리 (테스트 계속 진행)
        try:
            if dialog.type == 'beforeunload':
                dialog.dismiss()
            else:
                dialog.accept()  # alert는 accept만 가능
        except:
            pass

    def _handle_console(self, msg: ConsoleMessage):
        """
        Console 메시지 핸들러

        XSS로 인한 console.log 등을 감지합니다.
        """
        # XSS 관련 키워드 필터링
        text = msg.text.lower()
        xss_keywords = ['xss', 'alert', 'document.cookie', 'eval']

        if any(keyword in text for keyword in xss_keywords):
            evidence = XSSEvidence(
                evidence_type='console',
                description=f'Suspicious console.{msg.type}',
                timestamp=time.time(),
                details={
                    'type': msg.type,  # 'log', 'debug', 'info', 'error', 'warning'
                    'text': msg.text,
                    'location': msg.location
                }
            )
            self.evidences.append(evidence)

    def _handle_page_error(self, error: Exception):
        """
        페이지 에러 핸들러

        XSS로 인한 JavaScript 에러를 감지합니다.
        """
        evidence = XSSEvidence(
            evidence_type='page_error',
            description='JavaScript error occurred',
            timestamp=time.time(),
            details={
                'error': str(error)
            }
        )
        self.evidences.append(evidence)

    def verify_reflected_xss(
        self,
        url: str,
        payload: str,
        method: str = 'GET',
        post_data: Optional[Dict[str, str]] = None
    ) -> VerificationResult:
        """
        반사형 XSS 검증

        Args:
            url: 테스트할 URL (페이로드 포함)
            payload: 주입된 페이로드
            method: HTTP 메소드 ('GET' 또는 'POST')
            post_data: POST 데이터

        Returns:
            VerificationResult: 검증 결과
        """
        start_time = time.time()
        self.evidences = []  # 증거 초기화

        try:
            # 이벤트 핸들러 등록
            self._register_handlers()

            # 페이지 이동 (XSS 트리거)
            if method == 'GET':
                self.page.goto(url, wait_until='networkidle', timeout=self.timeout)
            else:
                # POST 요청은 evaluate로 form submit
                self._submit_post_form(url, post_data or {})

            # DOM이 안정화될 때까지 대기
            time.sleep(0.5)

            # 추가 증거 수집: DOM 변화 확인
            self._check_dom_changes(payload)

            # 실행 시간 계산
            execution_time = time.time() - start_time

            # 검증 성공 여부
            verified = len(self.evidences) > 0 and any(
                e.evidence_type in ['dialog', 'dom_change']
                for e in self.evidences
            )

            return VerificationResult(
                url=url,
                payload=payload,
                verified=verified,
                evidences=self.evidences.copy(),
                execution_time=execution_time
            )

        except Exception as e:
            execution_time = time.time() - start_time
            return VerificationResult(
                url=url,
                payload=payload,
                verified=False,
                evidences=self.evidences.copy(),
                execution_time=execution_time,
                error=str(e)
            )

        finally:
            # 핸들러 제거
            self._unregister_handlers()

    def verify_stored_xss(
        self,
        submit_url: str,
        submit_data: Dict[str, str],
        trigger_url: str,
        payload: str,
        submit_method: str = 'POST'
    ) -> VerificationResult:
        """
        저장형 XSS 검증

        1. 페이로드를 서버에 저장 (submit_url)
        2. 저장된 페이로드가 표시되는 페이지 방문 (trigger_url)
        3. XSS 실행 확인

        Args:
            submit_url: 페이로드를 저장할 URL
            submit_data: 저장할 데이터 (payload 포함)
            trigger_url: 저장된 페이로드가 표시되는 URL
            payload: 주입된 페이로드
            submit_method: 저장 요청 메소드

        Returns:
            VerificationResult: 검증 결과
        """
        start_time = time.time()
        self.evidences = []

        try:
            # STEP 1: 페이로드 저장
            if submit_method == 'GET':
                # GET으로 저장 (쿼리 파라미터)
                query_params = '&'.join([f"{k}={v}" for k, v in submit_data.items()])
                submit_full_url = f"{submit_url}?{query_params}"
                self.page.goto(submit_full_url, wait_until='networkidle', timeout=self.timeout)
            else:
                # POST로 저장
                self._submit_post_form(submit_url, submit_data)

            time.sleep(0.5)  # 서버 처리 대기

            # STEP 2: 이벤트 핸들러 등록
            self._register_handlers()

            # STEP 3: XSS가 트리거되는 페이지 방문
            self.page.goto(trigger_url, wait_until='networkidle', timeout=self.timeout)

            time.sleep(0.5)  # DOM 안정화

            # STEP 4: DOM 변화 확인
            self._check_dom_changes(payload)

            execution_time = time.time() - start_time

            verified = len(self.evidences) > 0 and any(
                e.evidence_type in ['dialog', 'dom_change']
                for e in self.evidences
            )

            return VerificationResult(
                url=trigger_url,
                payload=payload,
                verified=verified,
                evidences=self.evidences.copy(),
                execution_time=execution_time
            )

        except Exception as e:
            execution_time = time.time() - start_time
            return VerificationResult(
                url=trigger_url,
                payload=payload,
                verified=False,
                evidences=self.evidences.copy(),
                execution_time=execution_time,
                error=str(e)
            )

        finally:
            self._unregister_handlers()

    def _submit_post_form(self, url: str, data: Dict[str, str]):
        """
        POST 요청 전송 (form submit 방식)

        Args:
            url: POST URL
            data: POST 데이터
        """
        # 동적으로 form 생성하여 submit
        form_html = f"""
        <html>
        <body>
        <form id="xss_test_form" method="POST" action="{url}">
        """
        for key, value in data.items():
            # HTML escape 회피 (페이로드를 그대로 전송)
            escaped_value = value.replace('"', '&quot;')
            form_html += f'<input type="hidden" name="{key}" value="{escaped_value}">\n'

        form_html += """
        </form>
        <script>document.getElementById('xss_test_form').submit();</script>
        </body>
        </html>
        """

        # form HTML로 이동
        self.page.goto(f"data:text/html,{form_html}", wait_until='networkidle')

    def _check_dom_changes(self, payload: str):
        """
        DOM 변화 확인

        페이로드가 의도한 대로 HTML/JavaScript로 렌더링되었는지 확인합니다.

        Args:
            payload: 주입된 페이로드
        """
        try:
            # 현재 HTML 가져오기
            html = self.page.content()

            # 페이로드가 그대로 있는지 확인
            if payload in html:
                # 페이로드가 실행되지 않고 텍스트로만 표시됨
                return

            # XSS 흔적 찾기
            xss_indicators = [
                '<script>alert',
                '<img src=x onerror=',
                '<svg onload=',
                'javascript:alert',
                'onerror=',
                'onload=',
                'onclick=',
                'onmouseover='
            ]

            for indicator in xss_indicators:
                if indicator.lower() in html.lower():
                    evidence = XSSEvidence(
                        evidence_type='dom_change',
                        description=f'XSS payload rendered in DOM: {indicator}',
                        timestamp=time.time(),
                        details={
                            'indicator': indicator,
                            'payload_executed': True
                        }
                    )
                    self.evidences.append(evidence)
                    break

            # 특정 DOM 요소가 추가되었는지 확인 (예: <script> 태그)
            script_count = self.page.evaluate("""
                () => document.querySelectorAll('script').length
            """)

            img_with_onerror_count = self.page.evaluate("""
                () => document.querySelectorAll('img[onerror]').length
            """)

            if script_count > 0 or img_with_onerror_count > 0:
                evidence = XSSEvidence(
                    evidence_type='dom_change',
                    description='Suspicious DOM elements detected',
                    timestamp=time.time(),
                    details={
                        'script_tags': script_count,
                        'img_with_onerror': img_with_onerror_count
                    }
                )
                self.evidences.append(evidence)

        except Exception as e:
            # DOM 확인 실패는 무시
            pass

    def verify_batch(
        self,
        test_cases: List[Dict[str, Any]]
    ) -> List[VerificationResult]:
        """
        배치 검증

        여러 페이로드를 순차적으로 검증합니다.

        Args:
            test_cases: 테스트 케이스 리스트
                [
                    {
                        'url': 'http://...',
                        'payload': '<script>alert(1)</script>',
                        'method': 'GET'
                    },
                    ...
                ]

        Returns:
            List[VerificationResult]: 검증 결과 리스트
        """
        results = []

        for i, test_case in enumerate(test_cases, 1):
            print(f"[{i}/{len(test_cases)}] Verifying: {test_case.get('url', 'N/A')[:50]}...")

            result = self.verify_reflected_xss(
                url=test_case['url'],
                payload=test_case['payload'],
                method=test_case.get('method', 'GET'),
                post_data=test_case.get('post_data')
            )

            results.append(result)

            # 성공/실패 로그
            status = "[OK] VERIFIED" if result.verified else "[FAIL] NOT VERIFIED"
            print(f"    {status} ({len(result.evidences)} evidences)")

        return results


# ========================================
# 유틸리티 함수
# ========================================

def print_verification_result(result: VerificationResult):
    """검증 결과 출력"""
    print("\n" + "="*60)
    print("XSS Verification Result")
    print("="*60)

    print(f"\nURL: {result.url}")
    print(f"Payload: {result.payload[:100]}...")
    print(f"Verified: {'YES' if result.verified else 'NO'}")
    print(f"Execution Time: {result.execution_time:.2f}s")

    if result.error:
        print(f"Error: {result.error}")

    if result.evidences:
        print(f"\nEvidences ({len(result.evidences)}):")
        for i, evidence in enumerate(result.evidences, 1):
            print(f"\n  [{i}] {evidence.evidence_type.upper()}")
            print(f"      {evidence.description}")
            if evidence.details:
                for key, value in evidence.details.items():
                    print(f"      {key}: {value}")
    else:
        print("\nNo evidences found.")

    print("\n" + "="*60)


def summarize_batch_results(results: List[VerificationResult]):
    """배치 검증 결과 요약"""
    print("\n" + "="*60)
    print("Batch Verification Summary")
    print("="*60 + "\n")

    total = len(results)
    verified = sum(1 for r in results if r.verified)
    failed = total - verified

    print(f"Total: {total}")
    print(f"Verified: {verified} ({verified/total*100:.1f}%)")
    print(f"Failed: {failed} ({failed/total*100:.1f}%)")

    # 증거 타입별 통계
    evidence_types = {}
    for result in results:
        for evidence in result.evidences:
            evidence_types[evidence.evidence_type] = evidence_types.get(evidence.evidence_type, 0) + 1

    if evidence_types:
        print(f"\nEvidence Types:")
        for etype, count in sorted(evidence_types.items()):
            print(f"  - {etype}: {count}")

    print("\n" + "="*60)


if __name__ == "__main__":
    """
    테스트 코드

    실제 사용 예제는 tests/test_xss_verifier.py 참고
    """
    print("""
XSSVerifier Module

Usage:
    from playwright.sync_api import sync_playwright
    from xss_verifier import XSSVerifier

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        verifier = XSSVerifier(page)

        # 반사형 XSS 검증
        result = verifier.verify_reflected_xss(
            url='http://example.com/search?q=<script>alert(1)</script>',
            payload='<script>alert(1)</script>'
        )

        print(f"Verified: {result.verified}")
        print(f"Evidences: {len(result.evidences)}")

        browser.close()

For more examples, see tests/test_xss_verifier.py
""")
