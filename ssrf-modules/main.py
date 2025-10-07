"""
SSRF 퍼저 메인 실행 스크립트
크롤러 결과를 입력으로 받아 지능형 SSRF 테스트 수행
"""

import asyncio
import json
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Any
import time

# 모듈 임포트
from input.json_parser import SSRFTargetExtractor
from config.payloads import SSRFPayloadDatabase
from fuzzer.payload_engine import IntelligentPayloadEngine
from detector.multi_layer_detector import MultiLayerSSRFDetector
from collaborator.oob_server import OOBCollaborator


class SSRFFuzzer:
    """메인 SSRF 퍼저 클래스"""

    def __init__(self, collaborator_domain: str = "ssrf-test.local"):
        self.target_extractor = SSRFTargetExtractor()
        self.payload_db = SSRFPayloadDatabase()
        self.payload_engine = IntelligentPayloadEngine()
        self.detector = MultiLayerSSRFDetector()
        self.collaborator = OOBCollaborator(domain=collaborator_domain)

        self.session_id = None
        self.results = {
            'targets': [],
            'vulnerabilities': [],
            'statistics': {}
        }

    async def run_fuzzing(self, crawler_file: str, output_file: str = None,
                         min_risk: int = 30, max_targets: int = 10) -> Dict[str, Any]:
        """전체 퍼징 프로세스 실행"""

        print("=" * 60)
        print("SSRF 퍼저 시작")
        print("=" * 60)

        # 1. 크롤러 결과 로드 및 타겟 추출
        print("\n[1] 크롤러 결과 분석 중...")
        crawler_data = self.target_extractor.load_crawler_results(crawler_file)

        if not crawler_data:
            print("[!] 크롤러 데이터를 로드할 수 없습니다.")
            return self.results

        targets = self.target_extractor.extract_ssrf_targets(crawler_data)
        high_risk_targets = self.target_extractor.filter_targets_by_risk(targets, min_risk)

        # 타겟 수 제한
        test_targets = high_risk_targets[:max_targets]
        print(f"[+] 테스트 대상: {len(test_targets)}개 타겟")

        if not test_targets:
            print("[!] 테스트할 타겟이 없습니다.")
            return self.results

        # 2. OOB Collaborator 세션 생성
        print("\n[2] OOB Collaborator 설정 중...")
        self.session_id = self.collaborator.create_session("SSRF Fuzzing Session")

        # 3. 각 타겟에 대해 퍼징 수행
        print(f"\n[3] {len(test_targets)}개 타겟 퍼징 시작...")

        for i, target in enumerate(test_targets, 1):
            print(f"\n[{i}/{len(test_targets)}] 타겟 테스트: {target['url']}")

            try:
                vuln_result = await self._test_target(target)
                if vuln_result:
                    self.results['vulnerabilities'].append(vuln_result)
                    print(f"[!] 취약점 발견: {vuln_result['vulnerability_type']}")

            except Exception as e:
                print(f"[!] 타겟 테스트 오류: {e}")

        # 4. 결과 분석 및 저장
        print("\n[4] 결과 분석 중...")
        self._analyze_results()

        if output_file:
            self._save_results(output_file)
            print(f"[+] 결과 저장: {output_file}")

        # 5. 요약 출력
        self._print_summary()

        return self.results

    async def _test_target(self, target: Dict[str, Any]) -> Dict[str, Any]:
        """개별 타겟 테스트"""
        url = target['url']
        method = target['method']
        ssrf_params = target['ssrf_parameters']

        # 페이로드 생성
        payloads = self.payload_engine.generate_for_target(target)

        # OOB 페이로드 추가
        oob_dns = self.collaborator.generate_payload(self.session_id, 'dns')
        oob_http = self.collaborator.generate_payload(self.session_id, 'http')

        payloads.extend([
            {
                'payload': oob_dns['full_payload'],
                'description': 'OOB DNS test',
                'category': 'oob_dns',
                'risk_level': 'critical'
            },
            {
                'payload': oob_http['full_payload'],
                'description': 'OOB HTTP test',
                'category': 'oob_http',
                'risk_level': 'critical'
            }
        ])

        print(f"    페이로드 {len(payloads)}개 생성")

        vulnerabilities = []

        # 각 SSRF 파라미터에 대해 테스트
        for param in ssrf_params:
            param_name = param['name']
            print(f"    파라미터 테스트: {param_name}")

            # 페이로드별 테스트 (고급 기법 우선)
            # CRITICAL 우선순위는 모두 테스트, HIGH는 5개, 나머지는 3개
            critical_payloads = [p for p in payloads if p.get('priority') == 'critical']
            high_payloads = [p for p in payloads if p.get('priority') == 'high'][:5]
            other_payloads = [p for p in payloads if p.get('priority') not in ['critical', 'high']][:3]

            selected_payloads = critical_payloads + high_payloads + other_payloads
            print(f"    테스트 페이로드: Critical {len(critical_payloads)}개, High {len(high_payloads)}개, Others {len(other_payloads)}개")

            for payload in selected_payloads:
                test_result = await self._send_payload(
                    url, method, param_name, payload['payload']
                )

                if test_result:
                    # 멀티레이어 탐지 수행
                    detection_result = await self.detector.detect_ssrf(
                        url, payload['payload'], test_result
                    )

                    if detection_result['is_vulnerable']:
                        vuln = {
                            'target_url': url,
                            'method': method,
                            'parameter': param_name,
                            'payload': payload['payload'],
                            'vulnerability_type': detection_result['vulnerability_type'],
                            'confidence': detection_result['confidence'],
                            'evidence': detection_result['evidence'],
                            'timestamp': time.time()
                        }
                        vulnerabilities.append(vuln)

        # OOB 인터랙션 확인
        await asyncio.sleep(3)  # OOB 응답 대기
        oob_result = self.collaborator.detect_ssrf(self.session_id, timeout=5)

        if oob_result['ssrf_detected']:
            vuln = {
                'target_url': url,
                'method': method,
                'parameter': 'oob_test',
                'payload': 'OOB Collaborator',
                'vulnerability_type': 'blind_ssrf',
                'confidence': oob_result['confidence'],
                'evidence': oob_result['analysis'],
                'timestamp': time.time()
            }
            vulnerabilities.append(vuln)

        # 가장 높은 신뢰도 취약점 반환
        if vulnerabilities:
            return max(vulnerabilities, key=lambda x: x['confidence'])

        return None

    async def _send_payload(self, url: str, method: str, param_name: str,
                          payload: str) -> Dict[str, Any]:
        """페이로드 전송 및 응답 수집"""
        try:
            import aiohttp
            import time

            start_time = time.time()

            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                data = {param_name: payload}

                if method.upper() == 'GET':
                    async with session.get(url, params=data) as response:
                        content = await response.text()
                        end_time = time.time()

                        return {
                            'status_code': response.status,
                            'headers': dict(response.headers),
                            'content': content,
                            'response_time': end_time - start_time,
                            'url': str(response.url)
                        }
                else:
                    async with session.post(url, data=data) as response:
                        content = await response.text()
                        end_time = time.time()

                        return {
                            'status_code': response.status,
                            'headers': dict(response.headers),
                            'content': content,
                            'response_time': end_time - start_time,
                            'url': str(response.url)
                        }

        except Exception as e:
            print(f"    [!] 요청 실패: {e}")
            return None

    def _analyze_results(self):
        """결과 분석"""
        vulnerabilities = self.results['vulnerabilities']

        self.results['statistics'] = {
            'total_vulnerabilities': len(vulnerabilities),
            'critical_vulnerabilities': len([v for v in vulnerabilities if v['confidence'] >= 0.8]),
            'high_vulnerabilities': len([v for v in vulnerabilities if 0.6 <= v['confidence'] < 0.8]),
            'medium_vulnerabilities': len([v for v in vulnerabilities if 0.4 <= v['confidence'] < 0.6]),
            'vulnerability_types': {},
            'affected_parameters': set(),
            'affected_endpoints': set()
        }

        # 취약점 타입별 통계
        for vuln in vulnerabilities:
            vuln_type = vuln['vulnerability_type']
            if vuln_type not in self.results['statistics']['vulnerability_types']:
                self.results['statistics']['vulnerability_types'][vuln_type] = 0
            self.results['statistics']['vulnerability_types'][vuln_type] += 1

            self.results['statistics']['affected_parameters'].add(vuln['parameter'])
            self.results['statistics']['affected_endpoints'].add(vuln['target_url'])

        # set을 list로 변환 (JSON 직렬화를 위해)
        self.results['statistics']['affected_parameters'] = list(self.results['statistics']['affected_parameters'])
        self.results['statistics']['affected_endpoints'] = list(self.results['statistics']['affected_endpoints'])

    def _save_results(self, output_file: str):
        """결과 JSON 파일로 저장"""
        output_data = {
            'scan_info': {
                'timestamp': time.time(),
                'session_id': self.session_id,
                'tool': 'SSRF Fuzzer',
                'version': '1.0'
            },
            'statistics': self.results['statistics'],
            'vulnerabilities': self.results['vulnerabilities']
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)

    def _print_summary(self):
        """결과 요약 출력"""
        stats = self.results['statistics']

        print("\n" + "=" * 60)
        print("SSRF 퍼징 결과 요약")
        print("=" * 60)
        print(f"총 취약점: {stats['total_vulnerabilities']}개")
        print(f"심각 (80%+): {stats['critical_vulnerabilities']}개")
        print(f"높음 (60-79%): {stats['high_vulnerabilities']}개")
        print(f"중간 (40-59%): {stats['medium_vulnerabilities']}개")

        if stats['vulnerability_types']:
            print("\n취약점 타입별:")
            for vuln_type, count in stats['vulnerability_types'].items():
                print(f"  {vuln_type}: {count}개")

        if self.results['vulnerabilities']:
            print("\n발견된 취약점:")
            for i, vuln in enumerate(self.results['vulnerabilities'][:5], 1):
                print(f"  {i}. [{vuln['confidence']:.1%}] {vuln['target_url']}")
                print(f"     파라미터: {vuln['parameter']}, 타입: {vuln['vulnerability_type']}")

        print("=" * 60)


async def main():
    """메인 실행 함수"""
    parser = argparse.ArgumentParser(description='SSRF 퍼저')
    parser.add_argument('crawler_file', help='크롤러 JSON 결과 파일')
    parser.add_argument('-o', '--output', help='결과 출력 파일', default='ssrf_results.json')
    parser.add_argument('-r', '--min-risk', type=int, default=30, help='최소 위험도 (기본: 30)')
    parser.add_argument('-m', '--max-targets', type=int, default=10, help='최대 타겟 수 (기본: 10)')
    parser.add_argument('-d', '--domain', default='ssrf-test.local', help='OOB 도메인 (기본: ssrf-test.local)')

    args = parser.parse_args()

    # 파일 존재 확인
    if not Path(args.crawler_file).exists():
        print(f"[!] 크롤러 파일을 찾을 수 없습니다: {args.crawler_file}")
        sys.exit(1)

    # 퍼저 실행
    fuzzer = SSRFFuzzer(collaborator_domain=args.domain)

    try:
        results = await fuzzer.run_fuzzing(
            args.crawler_file,
            args.output,
            args.min_risk,
            args.max_targets
        )

        if results['statistics']['total_vulnerabilities'] > 0:
            sys.exit(1)  # 취약점 발견시 exit code 1
        else:
            sys.exit(0)  # 취약점 없음

    except KeyboardInterrupt:
        print("\n[!] 사용자 중단")
        sys.exit(130)
    except Exception as e:
        print(f"[!] 실행 오류: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
