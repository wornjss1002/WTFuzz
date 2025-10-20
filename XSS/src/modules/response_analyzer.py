"""
Response Analyzer Module
========================

응답 분석 및 취약점 판별 모듈
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
from datetime import datetime
from .detection_engine import DetectionResult, ConfidenceLevel


class XSSContext(Enum):
    """XSS 컨텍스트 타입"""
    REFLECTED = "reflected"
    STORED = "stored"
    DOM_BASED = "dom-based"
    UNKNOWN = "unknown"


class HTMLContext(Enum):
    """HTML 삽입 컨텍스트"""
    HTML_BODY = "html_body"
    HTML_ATTRIBUTE = "html_attribute"
    JAVASCRIPT = "javascript"
    CSS = "css"
    URL = "url"
    UNKNOWN = "unknown"


@dataclass
class Evidence:
    """취약점 증거"""
    screenshot: Optional[bytes] = None
    response_snippet: Optional[str] = None
    console_output: List[str] = field(default_factory=list)
    network_trace: Optional[Dict] = None
    dom_state: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            'has_screenshot': self.screenshot is not None,
            'response_snippet': self.response_snippet,
            'console_output': self.console_output,
            'network_trace': self.network_trace,
            'dom_state': self.dom_state[:500] if self.dom_state else None  # 처음 500자만
        }


@dataclass
class VulnerabilityReport:
    """취약점 리포트"""
    endpoint: str
    parameter: str
    payload: str
    detection_method: List[str]
    confidence: ConfidenceLevel
    context: XSSContext
    html_context: HTMLContext
    evidence: Evidence
    prevention_suggestions: List[str] = field(default_factory=list)
    severity: str = "high"
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict:
        return {
            'endpoint': self.endpoint,
            'parameter': self.parameter,
            'payload': self.payload,
            'detection_method': self.detection_method,
            'confidence': self.confidence.value,
            'context': self.context.value,
            'html_context': self.html_context.value,
            'evidence': self.evidence.to_dict(),
            'prevention_suggestions': self.prevention_suggestions,
            'severity': self.severity,
            'timestamp': self.timestamp.isoformat()
        }


class ResponseAnalyzer:
    """
    응답 분석기

    Features:
    - 컨텍스트 식별
    - 취약점 분류
    - 증거 수집 및 정리
    - 예방 제안 생성
    """

    @staticmethod
    def analyze(
        detection_result: DetectionResult,
        parameter_name: str
    ) -> Optional[VulnerabilityReport]:
        """
        탐지 결과 분석 및 취약점 리포트 생성

        Args:
            detection_result: Detection Engine의 결과
            parameter_name: 테스트한 파라미터 이름

        Returns:
            VulnerabilityReport 또는 None (취약점 없음)
        """
        # 탐지되지 않은 경우 None 반환
        if not detection_result.detected:
            return None

        # HTML 컨텍스트 식별
        html_context = ResponseAnalyzer._identify_html_context(
            detection_result.dom_snapshot,
            detection_result.payload
        )

        # XSS 컨텍스트 식별 (Reflected/Stored/DOM-based)
        xss_context = ResponseAnalyzer._identify_xss_context(
            detection_result
        )

        # 증거 수집
        evidence = ResponseAnalyzer._collect_evidence(detection_result)

        # 예방 제안 생성
        prevention_suggestions = ResponseAnalyzer._generate_prevention_suggestions(
            html_context,
            xss_context
        )

        # 심각도 판단
        severity = ResponseAnalyzer._determine_severity(
            detection_result.confidence,
            xss_context,
            html_context
        )

        # 리포트 생성
        report = VulnerabilityReport(
            endpoint=detection_result.url,
            parameter=parameter_name,
            payload=detection_result.payload,
            detection_method=detection_result.get_triggered_methods(),
            confidence=detection_result.confidence,
            context=xss_context,
            html_context=html_context,
            evidence=evidence,
            prevention_suggestions=prevention_suggestions,
            severity=severity
        )

        return report

    @staticmethod
    def _identify_html_context(dom_snapshot: Optional[str], payload: str) -> HTMLContext:
        """HTML 컨텍스트 식별"""
        if not dom_snapshot or not payload:
            return HTMLContext.UNKNOWN

        # 페이로드가 어디에 반영되었는지 찾기
        escaped_payload = re.escape(payload)

        # JavaScript 컨텍스트 체크
        js_pattern = rf'<script[^>]*>.*?{escaped_payload}.*?</script>'
        if re.search(js_pattern, dom_snapshot, re.IGNORECASE | re.DOTALL):
            return HTMLContext.JAVASCRIPT

        # HTML 속성 컨텍스트 체크
        attr_pattern = rf'<[^>]+\s+\w+=["\'].*?{escaped_payload}.*?["\']'
        if re.search(attr_pattern, dom_snapshot, re.IGNORECASE):
            return HTMLContext.HTML_ATTRIBUTE

        # CSS 컨텍스트 체크
        css_pattern = rf'<style[^>]*>.*?{escaped_payload}.*?</style>'
        if re.search(css_pattern, dom_snapshot, re.IGNORECASE | re.DOTALL):
            return HTMLContext.CSS

        # URL 컨텍스트 체크
        url_pattern = rf'(href|src)=["\'].*?{escaped_payload}.*?["\']'
        if re.search(url_pattern, dom_snapshot, re.IGNORECASE):
            return HTMLContext.URL

        # HTML 바디 컨텍스트
        if payload in dom_snapshot:
            return HTMLContext.HTML_BODY

        return HTMLContext.UNKNOWN

    @staticmethod
    def _identify_xss_context(detection_result: DetectionResult) -> XSSContext:
        """XSS 컨텍스트 식별"""
        # 간단한 휴리스틱:
        # - dialog나 console이 트리거되면 reflected 가능성 높음
        # - DOM mutation이 트리거되면 dom-based 가능성
        # - 실제로는 더 복잡한 분석 필요

        triggered_methods = detection_result.get_triggered_methods()

        if 'dialog' in triggered_methods or 'console' in triggered_methods:
            # 대부분의 경우 reflected XSS
            return XSSContext.REFLECTED

        if 'dom_mutation' in triggered_methods:
            # DOM 기반 XSS 가능성
            return XSSContext.DOM_BASED

        # 기본값
        return XSSContext.REFLECTED

    @staticmethod
    def _collect_evidence(detection_result: DetectionResult) -> Evidence:
        """증거 수집"""
        # 콘솔 출력 추출
        console_output = []
        for ev in detection_result.evidence:
            if ev.method.value == 'console' and ev.data:
                if isinstance(ev.data, list):
                    console_output.extend([msg.get('text', '') for msg in ev.data])

        # 응답 스니펫 추출 (페이로드 주변 200자)
        response_snippet = None
        if detection_result.dom_snapshot and detection_result.payload in detection_result.dom_snapshot:
            idx = detection_result.dom_snapshot.find(detection_result.payload)
            start = max(0, idx - 100)
            end = min(len(detection_result.dom_snapshot), idx + len(detection_result.payload) + 100)
            response_snippet = detection_result.dom_snapshot[start:end]

        # 네트워크 트레이스
        network_trace = None
        for ev in detection_result.evidence:
            if ev.method.value == 'network_activity' and ev.data:
                network_trace = ev.data

        return Evidence(
            screenshot=detection_result.screenshot,
            response_snippet=response_snippet,
            console_output=console_output,
            network_trace=network_trace,
            dom_state=detection_result.dom_snapshot
        )

    @staticmethod
    def _generate_prevention_suggestions(
        html_context: HTMLContext,
        xss_context: XSSContext
    ) -> List[str]:
        """예방 제안 생성"""
        suggestions = [
            "입력값 검증 및 새니타이징 구현",
            "Content Security Policy (CSP) 헤더 설정"
        ]

        # HTML 컨텍스트별 제안
        if html_context == HTMLContext.HTML_BODY:
            suggestions.extend([
                "HTML 엔티티 인코딩 (<, >, &, \", ') 적용",
                "안전한 HTML 파싱 라이브러리 사용 (DOMPurify 등)"
            ])
        elif html_context == HTMLContext.HTML_ATTRIBUTE:
            suggestions.extend([
                "속성값 따옴표로 감싸기",
                "속성 컨텍스트에 맞는 인코딩 적용",
                "위험한 속성(onclick, onerror 등) 필터링"
            ])
        elif html_context == HTMLContext.JAVASCRIPT:
            suggestions.extend([
                "JavaScript 문자열 이스케이핑",
                "JSON.stringify() 사용하여 안전한 데이터 전달",
                "eval() 사용 금지"
            ])
        elif html_context == HTMLContext.URL:
            suggestions.extend([
                "URL 인코딩 적용",
                "javascript: 프로토콜 필터링",
                "URL 화이트리스트 검증"
            ])

        # XSS 컨텍스트별 제안
        if xss_context == XSSContext.STORED:
            suggestions.append("저장 전 서버 사이드 검증 강화")
        elif xss_context == XSSContext.DOM_BASED:
            suggestions.extend([
                "안전한 DOM API 사용 (textContent, setAttribute)",
                "innerHTML 사용 금지",
                "클라이언트 사이드 입력 검증"
            ])

        # 일반 제안
        suggestions.extend([
            "HttpOnly 쿠키 플래그 설정",
            "X-XSS-Protection 헤더 활성화",
            "정기적인 보안 테스트 수행"
        ])

        return suggestions

    @staticmethod
    def _determine_severity(
        confidence: ConfidenceLevel,
        xss_context: XSSContext,
        html_context: HTMLContext
    ) -> str:
        """심각도 판단"""
        # 신뢰도가 낮으면 medium
        if confidence == ConfidenceLevel.LOW:
            return "medium"

        # Stored XSS는 항상 critical
        if xss_context == XSSContext.STORED:
            return "critical"

        # JavaScript 컨텍스트는 high
        if html_context == HTMLContext.JAVASCRIPT:
            return "high"

        # 기본값
        return "high"

    @staticmethod
    def batch_analyze(
        detection_results: List[DetectionResult],
        parameter_names: List[str]
    ) -> List[VulnerabilityReport]:
        """
        배치 분석

        Args:
            detection_results: DetectionResult 리스트
            parameter_names: 파라미터 이름 리스트

        Returns:
            VulnerabilityReport 리스트
        """
        reports = []

        for result, param_name in zip(detection_results, parameter_names):
            report = ResponseAnalyzer.analyze(result, param_name)
            if report:
                reports.append(report)

        return reports

    @staticmethod
    def generate_summary(reports: List[VulnerabilityReport]) -> Dict[str, Any]:
        """
        리포트 요약 생성

        Args:
            reports: VulnerabilityReport 리스트

        Returns:
            요약 정보 딕셔너리
        """
        if not reports:
            return {
                'total_vulnerabilities': 0,
                'by_severity': {},
                'by_context': {},
                'by_confidence': {}
            }

        # 심각도별 집계
        by_severity = {}
        for report in reports:
            by_severity[report.severity] = by_severity.get(report.severity, 0) + 1

        # 컨텍스트별 집계
        by_context = {}
        for report in reports:
            ctx = report.context.value
            by_context[ctx] = by_context.get(ctx, 0) + 1

        # 신뢰도별 집계
        by_confidence = {}
        for report in reports:
            conf = report.confidence.value
            by_confidence[conf] = by_confidence.get(conf, 0) + 1

        return {
            'total_vulnerabilities': len(reports),
            'by_severity': by_severity,
            'by_context': by_context,
            'by_confidence': by_confidence,
            'endpoints_affected': len(set(r.endpoint for r in reports)),
            'parameters_affected': len(set(r.parameter for r in reports))
        }


# 사용 예제
if __name__ == "__main__":
    from .detection_engine import DetectionEvidence, DetectionMethod

    # 테스트용 DetectionResult 생성
    test_result = DetectionResult(
        url="https://example.com/search?q=<script>alert(1)</script>",
        payload="<script>alert(1)</script>",
        detected=True,
        confidence=ConfidenceLevel.HIGH,
        evidence=[
            DetectionEvidence(
                method=DetectionMethod.DIALOG,
                triggered=True,
                data={'type': 'alert', 'message': '1'}
            ),
            DetectionEvidence(
                method=DetectionMethod.CONSOLE,
                triggered=True,
                data=[{'type': 'log', 'text': 'XSS detected'}]
            )
        ],
        dom_snapshot="<html><body><script>alert(1)</script></body></html>"
    )

    # 분석
    print("=== Response Analyzer 테스트 ===")
    report = ResponseAnalyzer.analyze(test_result, "q")

    if report:
        print(f"엔드포인트: {report.endpoint}")
        print(f"파라미터: {report.parameter}")
        print(f"페이로드: {report.payload}")
        print(f"신뢰도: {report.confidence.value}")
        print(f"컨텍스트: {report.context.value}")
        print(f"HTML 컨텍스트: {report.html_context.value}")
        print(f"심각도: {report.severity}")
        print(f"\n예방 제안:")
        for i, suggestion in enumerate(report.prevention_suggestions, 1):
            print(f"{i}. {suggestion}")
