"""
XSS Fuzzer - 메인 실행 모듈
============================

크롤러 → XSS Fuzzer → 익스플로잇 파이프라인

입력: 크롤러가 발견한 엔드포인트 (JSON)
출력: XSS 취약점 발견 결과 (JSON)
"""

import asyncio
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import List

# 공통 모델
sys.path.insert(0, str(Path(__file__).parent.parent))
from common.models import (
    Endpoint, XSSTestResult, XSSFuzzingResult,
    ConfidenceLevel, VulnerabilityType, ExploitTarget
)

# XSS 모듈
from src.modules.input_handler import InputHandler
from src.modules.payload_generator import PayloadGenerator, PayloadLevel
from src.modules.detection_engine import DetectionEngine


class XSSFuzzer:
    """
    XSS Fuzzer 메인 클래스

    역할:
    1. 크롤러 엔드포인트 입력받기
    2. 페이로드로 퍼징
    3. 취약점 탐지
    4. JSON 결과 반환 (익스플로잇 모듈로 전달)
    """

    def __init__(self, headless: bool = True, max_payloads_per_param: int = 10):
        """
        XSSFuzzer 초기화

        Args:
            headless: 브라우저 헤드리스 모드
            max_payloads_per_param: 파라미터당 최대 페이로드 수
        """
        self.payload_gen = PayloadGenerator()
        self.detection_engine = None
        self.headless = headless
        self.max_payloads = max_payloads_per_param

    async def initialize(self):
        """비동기 초기화 (브라우저 시작)"""
        self.detection_engine = DetectionEngine(headless=self.headless)
        await self.detection_engine.initialize()

    async def close(self):
        """리소스 정리"""
        if self.detection_engine:
            await self.detection_engine.close()

    async def fuzz_endpoint(
        self,
        endpoint: Endpoint,
        level: PayloadLevel = PayloadLevel.LEVEL_1
    ) -> List[XSSTestResult]:
        """
        단일 엔드포인트 퍼징

        Args:
            endpoint: 테스트할 엔드포인트
            level: 페이로드 레벨 (1-4)

        Returns:
            XSSTestResult 리스트
        """
        results = []

        # 테스트 가능한 파라미터 추출
        testable_params = InputHandler.get_testable_parameters(endpoint)

        if not testable_params:
            print(f"[!] 테스트 가능한 파라미터 없음: {endpoint.url}")
            return results

        # 페이로드 가져오기
        payloads = self.payload_gen.get_payloads_by_level(level)
        payloads = payloads[:self.max_payloads]  # 제한

        print(f"[*] 테스트 시작: {endpoint.url}")
        print(f"    - 파라미터: {len(testable_params)}개")
        print(f"    - 페이로드: {len(payloads)}개")

        # 각 파라미터별로 퍼징
        for param in testable_params:
            print(f"  [*] 파라미터 테스트: {param.name}")

            for payload in payloads:
                # 테스트 URL 생성
                test_url = InputHandler.build_test_url(
                    endpoint,
                    param.name,
                    payload.payload
                )

                try:
                    # XSS 탐지
                    detection_result = await self.detection_engine.detect_xss(
                        url=test_url,
                        payload=payload.payload
                    )

                    # 결과 변환
                    if detection_result.detected:
                        print(f"    [+] 취약점 발견! 페이로드: {payload.id}")

                        xss_result = XSSTestResult(
                            endpoint=endpoint.url,
                            parameter=param.name,
                            payload=payload.payload,
                            vulnerable=True,
                            confidence=detection_result.confidence,
                            detection_methods=detection_result.get_triggered_methods(),
                            evidence=[],  # 간소화: 상세 증거는 생략
                            execution_time=detection_result.execution_time
                        )
                        results.append(xss_result)

                        # 첫 성공 시 해당 파라미터는 스킵 (시간 절약)
                        break

                except Exception as e:
                    print(f"    [!] 오류: {str(e)}")
                    continue

        return results

    async def fuzz_endpoints(
        self,
        endpoints: List[Endpoint],
        level: PayloadLevel = PayloadLevel.LEVEL_1
    ) -> XSSFuzzingResult:
        """
        여러 엔드포인트 퍼징

        Args:
            endpoints: 엔드포인트 리스트
            level: 페이로드 레벨

        Returns:
            XSSFuzzingResult (전체 결과)
        """
        start_time = datetime.now()

        print(f"\n{'='*60}")
        print(f"XSS Fuzzer 시작")
        print(f"{'='*60}")
        print(f"대상 엔드포인트: {len(endpoints)}개")
        print(f"페이로드 레벨: {level.value}")
        print(f"{'='*60}\n")

        all_vulnerabilities = []
        safe_endpoints = []

        # 각 엔드포인트 퍼징
        for i, endpoint in enumerate(endpoints, 1):
            print(f"\n[{i}/{len(endpoints)}] {endpoint.url}")

            # 유효성 검증
            is_valid, msg = InputHandler.validate_endpoint(endpoint)
            if not is_valid:
                print(f"[!] 스킵: {msg}")
                continue

            # 퍼징
            results = await self.fuzz_endpoint(endpoint, level)

            if results:
                all_vulnerabilities.extend(results)
            else:
                safe_endpoints.append(endpoint.url)

        # 최종 결과
        end_time = datetime.now()

        fuzzing_result = XSSFuzzingResult(
            total_endpoints=len(endpoints),
            total_tests=sum(len(InputHandler.get_testable_parameters(ep)) for ep in endpoints),
            vulnerable_endpoints=all_vulnerabilities,
            safe_endpoints=safe_endpoints,
            start_time=start_time,
            end_time=end_time
        )

        return fuzzing_result

    def export_results(self, result: XSSFuzzingResult, output_file: str):
        """
        결과를 JSON 파일로 저장

        Args:
            result: 퍼징 결과
            output_file: 출력 파일 경로
        """
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result.to_dict(), f, ensure_ascii=False, indent=2)

        print(f"\n[+] 결과 저장: {output_file}")

    def export_for_exploit(self, result: XSSFuzzingResult, output_file: str):
        """
        익스플로잇 모듈 입력용 JSON 생성

        Args:
            result: 퍼징 결과
            output_file: 출력 파일 경로
        """
        exploit_targets = []

        for vuln in result.vulnerable_endpoints:
            target = ExploitTarget(
                vuln_type=VulnerabilityType.XSS,
                endpoint=vuln.endpoint,
                parameter=vuln.parameter,
                successful_payload=vuln.payload,
                confidence=vuln.confidence,
                additional_info={
                    'detection_methods': vuln.detection_methods,
                    'execution_time': vuln.execution_time
                }
            )
            exploit_targets.append(target.to_dict())

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(exploit_targets, f, ensure_ascii=False, indent=2)

        print(f"[+] 익스플로잇 입력 파일 생성: {output_file}")


# ==================== 메인 실행 ====================

async def main():
    """메인 함수"""
    import argparse

    parser = argparse.ArgumentParser(description='XSS Fuzzer - 크롤러 엔드포인트를 XSS 퍼징')
    parser.add_argument('-i', '--input', required=True, help='크롤러 출력 JSON 파일')
    parser.add_argument('-o', '--output', default='xss_results.json', help='결과 출력 파일')
    parser.add_argument('-e', '--exploit-output', default='exploit_input.json', help='익스플로잇 모듈 입력 파일')
    parser.add_argument('-l', '--level', type=int, default=1, choices=[1, 2, 3, 4], help='페이로드 레벨 (1-4)')
    parser.add_argument('--max-payloads', type=int, default=10, help='파라미터당 최대 페이로드 수')
    parser.add_argument('--headless', action='store_true', help='헤드리스 모드')

    args = parser.parse_args()

    # 엔드포인트 로드
    print(f"[*] 크롤러 데이터 로드: {args.input}")
    try:
        endpoints = InputHandler.from_json_file(args.input)
        print(f"[+] {len(endpoints)}개 엔드포인트 로드 완료\n")
    except Exception as e:
        print(f"[!] 오류: {str(e)}")
        return

    # Fuzzer 초기화
    fuzzer = XSSFuzzer(
        headless=args.headless,
        max_payloads_per_param=args.max_payloads
    )

    try:
        await fuzzer.initialize()

        # 퍼징 실행
        level = PayloadLevel(args.level)
        result = await fuzzer.fuzz_endpoints(endpoints, level)

        # 결과 출력
        print(f"\n{'='*60}")
        print(f"XSS Fuzzer 완료")
        print(f"{'='*60}")
        print(f"총 엔드포인트: {result.total_endpoints}개")
        print(f"취약 엔드포인트: {len(result.vulnerable_endpoints)}개")
        print(f"안전 엔드포인트: {len(result.safe_endpoints)}개")
        print(f"소요 시간: {(result.end_time - result.start_time).total_seconds():.2f}초")
        print(f"{'='*60}\n")

        # 결과 저장
        fuzzer.export_results(result, args.output)
        fuzzer.export_for_exploit(result, args.exploit_output)

        print("\n[+] XSS Fuzzer 작업 완료!")

    finally:
        await fuzzer.close()


if __name__ == "__main__":
    asyncio.run(main())
