"""
Input Handler Module
====================

크롤러에서 받은 엔드포인트를 XSS 퍼징을 위해 처리
"""

import sys
import json
from typing import List, Dict
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# 공통 모델 import
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.models import HTTPMethod, ParameterType, Parameter, Endpoint, endpoint_from_dict


class InputHandler:
    """
    크롤러 → XSS 모듈 입력 처리

    역할:
    - 크롤러가 발견한 엔드포인트 로드
    - JSON 파일에서 엔드포인트 읽기
    - 테스트용 URL 생성 (페이로드 삽입)
    """

    @staticmethod
    def from_json_file(file_path: str) -> List[Endpoint]:
        """
        크롤러가 생성한 JSON 파일에서 엔드포인트 로드

        Args:
            file_path: 크롤러 출력 JSON 파일 경로

        Returns:
            Endpoint 리스트
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        endpoints = []
        if isinstance(data, list):
            for item in data:
                endpoints.append(endpoint_from_dict(item))
        else:
            endpoints.append(endpoint_from_dict(data))

        return endpoints

    @staticmethod
    def from_dict_list(data_list: List[Dict]) -> List[Endpoint]:
        """
        딕셔너리 리스트에서 Endpoint 생성

        Args:
            data_list: 엔드포인트 데이터 딕셔너리 리스트

        Returns:
            Endpoint 리스트
        """
        return [endpoint_from_dict(data) for data in data_list]

    @staticmethod
    def build_test_url(endpoint: Endpoint, param_name: str, payload: str) -> str:
        """
        페이로드가 삽입된 테스트 URL 생성

        Args:
            endpoint: 대상 엔드포인트
            param_name: 페이로드를 삽입할 파라미터 이름
            payload: XSS 페이로드

        Returns:
            테스트용 URL
        """
        parsed = urlparse(endpoint.url)
        params = parse_qs(parsed.query)

        # 페이로드 삽입
        params[param_name] = [payload]

        # URL 재구성
        new_query = urlencode(params, doseq=True)
        test_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))

        return test_url

    @staticmethod
    def get_testable_parameters(endpoint: Endpoint) -> List[Parameter]:
        """
        테스트 가능한 파라미터만 필터링

        Args:
            endpoint: 엔드포인트

        Returns:
            테스트 가능한 파라미터 리스트
        """
        # query와 body 파라미터만 XSS 테스트 대상
        return [
            p for p in endpoint.parameters
            if p.param_type in [ParameterType.QUERY, ParameterType.BODY]
        ]

    @staticmethod
    def validate_endpoint(endpoint: Endpoint) -> tuple[bool, str]:
        """
        엔드포인트 유효성 검증

        Args:
            endpoint: 검증할 엔드포인트

        Returns:
            (유효 여부, 메시지)
        """
        # URL 검증
        try:
            parsed = urlparse(endpoint.url)
            if not parsed.scheme:
                return False, "URL 스키마가 없습니다"
            if not parsed.netloc:
                return False, "URL 도메인이 없습니다"
            if parsed.scheme not in ['http', 'https']:
                return False, f"지원하지 않는 프로토콜: {parsed.scheme}"
        except Exception as e:
            return False, f"URL 파싱 오류: {str(e)}"

        # 파라미터 검증
        testable_params = InputHandler.get_testable_parameters(endpoint)
        if not testable_params:
            return False, "테스트 가능한 파라미터가 없습니다"

        return True, "OK"


# 사용 예제
if __name__ == "__main__":
    # 크롤러 출력 파일에서 엔드포인트 로드
    print("=== InputHandler 테스트 ===")

    # 테스트용 데이터
    test_data = [
        {
            "url": "https://example.com/search?q=test&page=1",
            "method": "GET",
            "parameters": [
                {"name": "q", "type": "query", "value": "test", "required": False},
                {"name": "page", "type": "query", "value": "1", "required": False}
            ],
            "headers": {},
            "cookies": {},
            "discovered_by": "crawler"
        }
    ]

    # 엔드포인트 로드
    endpoints = InputHandler.from_dict_list(test_data)

    print(f"로드된 엔드포인트: {len(endpoints)}개")
    for ep in endpoints:
        print(f"- URL: {ep.url}")
        print(f"- Method: {ep.method.value}")
        print(f"- 파라미터: {len(ep.parameters)}개")

        # 검증
        is_valid, msg = InputHandler.validate_endpoint(ep)
        print(f"- 유효성: {is_valid} ({msg})")

        # 테스트 URL 생성
        if is_valid:
            params = InputHandler.get_testable_parameters(ep)
            for param in params:
                test_url = InputHandler.build_test_url(ep, param.name, "<script>alert(1)</script>")
                print(f"- 테스트 URL ({param.name}): {test_url}")
