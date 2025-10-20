"""
Payload Generator Module
========================

XSS 페이로드 생성 및 관리 모듈
"""

import json
import os
import sys
from typing import List, Dict, Optional, Set
from pathlib import Path
from enum import Enum

# 공통 모델 import
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.models import Payload


class PayloadCategory(Enum):
    """페이로드 카테고리"""
    BASIC = "basic"
    BYPASS = "bypass"
    CONTEXT_AWARE = "context_aware"
    ENCODING = "encoding"


class PayloadLevel(Enum):
    """페이로드 공격 레벨"""
    LEVEL_1 = 1  # Basic payloads
    LEVEL_2 = 2  # Bypass payloads
    LEVEL_3 = 3  # Context-aware payloads
    LEVEL_4 = 4  # Encoding variations


class PayloadGenerator:
    """
    XSS 페이로드 생성기

    Features:
    - 다단계 페이로드 전략
    - 컨텍스트 기반 필터링
    - 동적 페이로드 변형
    - 페이로드 추적 및 중복 방지
    """

    def __init__(self, payloads_dir: Optional[str] = None):
        """
        PayloadGenerator 초기화

        Args:
            payloads_dir: 페이로드 JSON 파일이 있는 디렉토리 경로
        """
        if payloads_dir is None:
            # 기본 경로: 프로젝트 루트의 payloads 디렉토리
            project_root = Path(__file__).parent.parent.parent
            payloads_dir = project_root / "payloads"

        self.payloads_dir = Path(payloads_dir)
        self.payloads: Dict[str, List[Payload]] = {}
        self.used_payloads: Set[str] = set()

        # 페이로드 로드
        self._load_payloads()

    def _load_payloads(self) -> None:
        """
        JSON 파일에서 페이로드 로드
        """
        if not self.payloads_dir.exists():
            raise FileNotFoundError(f"페이로드 디렉토리를 찾을 수 없습니다: {self.payloads_dir}")

        payload_files = {
            PayloadCategory.BASIC.value: "basic.json",
            PayloadCategory.BYPASS.value: "bypass.json",
            PayloadCategory.CONTEXT_AWARE.value: "context_aware.json",
            PayloadCategory.ENCODING.value: "encoding.json",
        }

        for category, filename in payload_files.items():
            file_path = self.payloads_dir / filename
            if file_path.exists():
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.payloads[category] = [
                        Payload(
                            id=p['id'],
                            payload=p['payload'],
                            category=category,
                            context=p['context'],
                            severity=p['severity']
                        )
                        for p in data['payloads']
                    ]
            else:
                print(f"경고: {filename} 파일을 찾을 수 없습니다.")
                self.payloads[category] = []

    def get_payloads_by_level(self, level: PayloadLevel) -> List[Payload]:
        """
        레벨별 페이로드 반환

        Args:
            level: 페이로드 레벨 (1-4)

        Returns:
            해당 레벨의 페이로드 리스트
        """
        level_mapping = {
            PayloadLevel.LEVEL_1: [PayloadCategory.BASIC],
            PayloadLevel.LEVEL_2: [PayloadCategory.BASIC, PayloadCategory.BYPASS],
            PayloadLevel.LEVEL_3: [
                PayloadCategory.BASIC,
                PayloadCategory.BYPASS,
                PayloadCategory.CONTEXT_AWARE
            ],
            PayloadLevel.LEVEL_4: [
                PayloadCategory.BASIC,
                PayloadCategory.BYPASS,
                PayloadCategory.CONTEXT_AWARE,
                PayloadCategory.ENCODING
            ],
        }

        categories = level_mapping.get(level, [])
        result = []

        for category in categories:
            result.extend(self.payloads.get(category.value, []))

        return result

    def get_payloads_by_context(self, context: str) -> List[Payload]:
        """
        컨텍스트별 페이로드 필터링

        Args:
            context: HTML 컨텍스트 (html, script, attribute, css 등)

        Returns:
            해당 컨텍스트에 맞는 페이로드 리스트
        """
        result = []
        for category_payloads in self.payloads.values():
            for payload in category_payloads:
                if context in payload.context:
                    result.append(payload)
        return result

    def get_payloads_by_category(self, category: PayloadCategory) -> List[Payload]:
        """
        카테고리별 페이로드 반환

        Args:
            category: 페이로드 카테고리

        Returns:
            해당 카테고리의 페이로드 리스트
        """
        return self.payloads.get(category.value, [])

    def get_progressive_payloads(
        self,
        context: Optional[str] = None,
        max_level: PayloadLevel = PayloadLevel.LEVEL_4
    ) -> Dict[int, List[Payload]]:
        """
        점진적 페이로드 전략 - 레벨별로 페이로드 반환

        Args:
            context: 필터링할 HTML 컨텍스트 (선택사항)
            max_level: 최대 레벨

        Returns:
            레벨별 페이로드 딕셔너리
        """
        result = {}

        for level in PayloadLevel:
            if level.value > max_level.value:
                break

            payloads = self.get_payloads_by_level(level)

            # 컨텍스트 필터링
            if context:
                payloads = [p for p in payloads if context in p.context]

            # 중복 제거 (이전 레벨에서 사용된 페이로드 제외)
            unique_payloads = []
            for p in payloads:
                if p.id not in self.used_payloads:
                    unique_payloads.append(p)
                    self.used_payloads.add(p.id)

            result[level.value] = unique_payloads

        return result

    def generate_custom_payload(
        self,
        base_payload: str,
        variations: Optional[List[str]] = None
    ) -> List[str]:
        """
        베이스 페이로드로부터 변형된 페이로드 생성

        Args:
            base_payload: 기본 페이로드
            variations: 적용할 변형 리스트

        Returns:
            변형된 페이로드 리스트
        """
        if variations is None:
            variations = ['case_mix', 'encoding', 'whitespace']

        results = [base_payload]

        if 'case_mix' in variations:
            # 대소문자 혼합
            results.append(self._mix_case(base_payload))

        if 'encoding' in variations:
            # URL 인코딩
            results.append(self._url_encode(base_payload))

        if 'whitespace' in variations:
            # 공백 변형
            results.extend(self._whitespace_variations(base_payload))

        return results

    def _mix_case(self, payload: str) -> str:
        """대소문자 혼합"""
        result = []
        for i, char in enumerate(payload):
            if i % 2 == 0:
                result.append(char.upper())
            else:
                result.append(char.lower())
        return ''.join(result)

    def _url_encode(self, payload: str) -> str:
        """URL 인코딩"""
        from urllib.parse import quote
        return quote(payload)

    def _whitespace_variations(self, payload: str) -> List[str]:
        """공백 변형"""
        variations = []
        # 탭으로 대체
        variations.append(payload.replace(' ', '\t'))
        # 줄바꿈으로 대체
        variations.append(payload.replace(' ', '\n'))
        # 슬래시로 대체
        variations.append(payload.replace(' ', '/'))
        return variations

    def get_all_payloads(self) -> List[Payload]:
        """
        모든 페이로드 반환

        Returns:
            전체 페이로드 리스트
        """
        result = []
        for category_payloads in self.payloads.values():
            result.extend(category_payloads)
        return result

    def get_payload_count(self) -> Dict[str, int]:
        """
        카테고리별 페이로드 개수 반환

        Returns:
            카테고리별 개수 딕셔너리
        """
        return {
            category: len(payloads)
            for category, payloads in self.payloads.items()
        }

    def reset_used_payloads(self) -> None:
        """사용된 페이로드 추적 초기화"""
        self.used_payloads.clear()

    def get_statistics(self) -> Dict[str, any]:
        """
        페이로드 통계 정보 반환

        Returns:
            통계 정보 딕셔너리
        """
        total = sum(len(payloads) for payloads in self.payloads.values())

        return {
            'total_payloads': total,
            'by_category': self.get_payload_count(),
            'used_payloads': len(self.used_payloads),
            'available_payloads': total - len(self.used_payloads),
        }


# 사용 예제
if __name__ == "__main__":
    # 페이로드 생성기 초기화
    generator = PayloadGenerator()

    # 통계 출력
    print("=== 페이로드 통계 ===")
    stats = generator.get_statistics()
    print(f"전체 페이로드: {stats['total_payloads']}")
    print(f"카테고리별 개수: {stats['by_category']}")

    # 레벨 1 페이로드 가져오기
    print("\n=== Level 1 페이로드 ===")
    level1_payloads = generator.get_payloads_by_level(PayloadLevel.LEVEL_1)
    for p in level1_payloads[:5]:  # 처음 5개만 출력
        print(f"{p.id}: {p.payload}")

    # HTML 컨텍스트 페이로드 가져오기
    print("\n=== HTML 컨텍스트 페이로드 ===")
    html_payloads = generator.get_payloads_by_context('html')
    print(f"HTML 컨텍스트 페이로드 개수: {len(html_payloads)}")

    # 점진적 페이로드 전략
    print("\n=== 점진적 페이로드 전략 ===")
    progressive = generator.get_progressive_payloads(context='html', max_level=PayloadLevel.LEVEL_2)
    for level, payloads in progressive.items():
        print(f"Level {level}: {len(payloads)} 페이로드")
