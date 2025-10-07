"""
크롤러 JSON 결과 파싱 및 SSRF 타겟 추출
"""

import json
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs
from pathlib import Path


class SSRFTargetExtractor:
    """크롤러 결과에서 SSRF 가능성이 높은 타겟 추출"""

    def __init__(self):
        # SSRF 가능성이 높은 파라미터 패턴
        self.ssrf_param_patterns = [
            r'url', r'uri', r'link', r'redirect', r'callback',
            r'fetch', r'load', r'import', r'include', r'file',
            r'path', r'source', r'target', r'dest', r'endpoint',
            r'api', r'proxy', r'forward', r'goto', r'next'
        ]

        # SSRF 위험도가 높은 엔드포인트 패턴
        self.high_risk_endpoints = [
            r'/api/', r'/upload', r'/proxy', r'/redirect',
            r'/fetch', r'/import', r'/include', r'/download',
            r'/webhook', r'/callback', r'/forward'
        ]

    def load_crawler_results(self, json_file: str) -> Dict[str, Any]:
        """크롤러 JSON 결과 로드"""
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            print(f"[+] 크롤러 결과 로드: {json_file}")
            return data
        except Exception as e:
            print(f"[!] JSON 로드 실패: {e}")
            return {}

    def extract_ssrf_targets(self, crawler_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """SSRF 타겟 추출"""
        targets = []

        if not crawler_data.get('endpoints'):
            print("[!] 엔드포인트 데이터가 없습니다")
            return targets

        print(f"[+] {len(crawler_data['endpoints'])}개 엔드포인트 분석 중...")

        for endpoint in crawler_data['endpoints']:
            target = self._analyze_endpoint(endpoint)
            if target:
                targets.append(target)

        # 위험도별 정렬
        targets.sort(key=lambda x: x['risk_score'], reverse=True)

        print(f"[+] {len(targets)}개 SSRF 타겟 발견")
        return targets

    def _analyze_endpoint(self, endpoint: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """개별 엔드포인트 SSRF 가능성 분석"""
        url = endpoint.get('url', '')
        method = endpoint.get('method', 'GET')
        parameters = endpoint.get('parameters', [])

        if not parameters:
            return None

        # SSRF 가능 파라미터 찾기
        ssrf_params = []
        risk_score = 0

        for param in parameters:
            param_name = param.get('name', '').lower()
            param_type = param.get('type', '')
            location = param.get('location', '')

            # 파라미터 이름 기반 위험도 계산
            param_risk = self._calculate_param_risk(param_name, param_type)

            if param_risk > 0:
                ssrf_params.append({
                    'name': param['name'],
                    'type': param_type,
                    'location': location,
                    'risk_score': param_risk,
                    'default_value': param.get('default_value', ''),
                    'required': param.get('required', False)
                })
                risk_score += param_risk

        if not ssrf_params:
            return None

        # 엔드포인트 URL 기반 위험도 추가
        endpoint_risk = self._calculate_endpoint_risk(url)
        risk_score += endpoint_risk

        return {
            'url': url,
            'method': method,
            'ssrf_parameters': ssrf_params,
            'risk_score': min(risk_score, 100),  # 최대 100점
            'endpoint_type': self._classify_endpoint(url),
            'source': endpoint.get('source', 'unknown')
        }

    def _calculate_param_risk(self, param_name: str, param_type: str) -> int:
        """파라미터 위험도 계산 (0-50점)"""
        risk = 0

        # 파라미터 이름 패턴 매칭
        for pattern in self.ssrf_param_patterns:
            if re.search(pattern, param_name, re.IGNORECASE):
                if pattern in ['url', 'uri', 'link']:
                    risk += 30  # 매우 높은 위험
                elif pattern in ['redirect', 'callback', 'fetch']:
                    risk += 25  # 높은 위험
                elif pattern in ['file', 'path', 'source']:
                    risk += 20  # 중간 위험
                else:
                    risk += 15  # 낮은 위험
                break

        # 파라미터 타입 기반 추가 점수
        if param_type in ['text', 'url', 'textarea']:
            risk += 10
        elif param_type == 'hidden':
            risk += 5

        return min(risk, 50)

    def _calculate_endpoint_risk(self, url: str) -> int:
        """엔드포인트 위험도 계산 (0-30점)"""
        risk = 0

        # URL 패턴 매칭
        for pattern in self.high_risk_endpoints:
            if re.search(pattern, url, re.IGNORECASE):
                risk += 20
                break

        # 특정 기능 키워드 확인
        high_risk_keywords = ['admin', 'api', 'webhook', 'proxy']
        for keyword in high_risk_keywords:
            if keyword in url.lower():
                risk += 10
                break

        return min(risk, 30)

    def _classify_endpoint(self, url: str) -> str:
        """엔드포인트 유형 분류"""
        url_lower = url.lower()

        if '/api/' in url_lower:
            return 'api'
        elif any(keyword in url_lower for keyword in ['upload', 'file']):
            return 'file_upload'
        elif any(keyword in url_lower for keyword in ['redirect', 'forward']):
            return 'redirect'
        elif any(keyword in url_lower for keyword in ['proxy', 'fetch']):
            return 'proxy'
        elif any(keyword in url_lower for keyword in ['webhook', 'callback']):
            return 'webhook'
        elif any(keyword in url_lower for keyword in ['admin', 'manage']):
            return 'admin'
        else:
            return 'general'

    def filter_targets_by_risk(self, targets: List[Dict[str, Any]], min_risk: int = 30) -> List[Dict[str, Any]]:
        """위험도 기준 타겟 필터링"""
        filtered = [t for t in targets if t['risk_score'] >= min_risk]
        print(f"[+] 위험도 {min_risk}점 이상: {len(filtered)}개 타겟")
        return filtered

    def export_targets(self, targets: List[Dict[str, Any]], output_file: str) -> None:
        """SSRF 타겟을 JSON으로 저장"""
        output_data = {
            'generated_at': __import__('datetime').datetime.now().isoformat(),
            'total_targets': len(targets),
            'high_risk_targets': len([t for t in targets if t['risk_score'] >= 70]),
            'medium_risk_targets': len([t for t in targets if 40 <= t['risk_score'] < 70]),
            'low_risk_targets': len([t for t in targets if t['risk_score'] < 40]),
            'targets': targets
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)

        print(f"[+] SSRF 타겟 저장: {output_file}")
        self._print_summary(output_data)

    def _print_summary(self, data: Dict[str, Any]) -> None:
        """타겟 요약 출력"""
        print("\n" + "="*60)
        print("SSRF 타겟 추출 요약")
        print("="*60)
        print(f"총 타겟: {data['total_targets']}개")
        print(f"고위험 (70점+): {data['high_risk_targets']}개")
        print(f"중위험 (40-69점): {data['medium_risk_targets']}개")
        print(f"저위험 (40점 미만): {data['low_risk_targets']}개")

        # 상위 10개 타겟 출력
        if data['targets']:
            print("\n상위 위험 타겟:")
            for i, target in enumerate(data['targets'][:10], 1):
                param_names = [p['name'] for p in target['ssrf_parameters']]
                print(f"  {i}. [{target['risk_score']:2d}점] {target['method']} {target['url']}")
                print(f"     파라미터: {', '.join(param_names)}")

        print("="*60)


def main():
    """테스트 실행"""
    extractor = SSRFTargetExtractor()

    # 크롤러 결과 로드
    crawler_file = "../crawler 1/dynamic_crawl_results.json"
    crawler_data = extractor.load_crawler_results(crawler_file)

    if not crawler_data:
        print("크롤러 데이터를 로드할 수 없습니다.")
        return

    # SSRF 타겟 추출
    targets = extractor.extract_ssrf_targets(crawler_data)

    if targets:
        # 고위험 타겟만 필터링
        high_risk_targets = extractor.filter_targets_by_risk(targets, min_risk=30)

        # 결과 저장
        output_file = "ssrf_targets.json"
        extractor.export_targets(high_risk_targets, output_file)
    else:
        print("[!] SSRF 타겟을 찾을 수 없습니다.")


if __name__ == "__main__":
    main()
