"""
멀티레이어 SSRF 탐지 시스템 - 4계층 간접 신호 분석
"""

import time
import re
import statistics
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse
from dataclasses import dataclass


@dataclass
class TimingData:
    """타이밍 데이터 구조"""
    total_time: float
    dns_time: float
    connect_time: float
    response_time: float
    redirect_time: float = 0.0


@dataclass
class DetectionResult:
    """탐지 결과 구조"""
    ssrf_detected: bool
    confidence: float
    detection_layers: Dict[str, float]
    evidence: List[str]
    risk_level: str
    recommended_actions: List[str]


class TimingDetector:
    """1계층: 타이밍 기반 탐지"""

    def __init__(self):
        self.baseline_times = {}
        self.timeout_threshold = 10.0  # 10초
        self.dns_delay_threshold = 100  # 100ms

    def analyze_timing_patterns(self, payload: str, timing: TimingData, baseline: Optional[TimingData] = None) -> Dict[str, Any]:
        """타이밍 패턴 분석"""
        results = {
            'score': 0.0,
            'indicators': [],
            'anomalies': []
        }

        # 1. DNS 지연 분석
        if timing.dns_time > self.dns_delay_threshold:
            results['score'] += 0.3
            results['indicators'].append(f'DNS delay: {timing.dns_time:.2f}ms')

        # 2. 전체 응답 시간 분석
        if timing.total_time > self.timeout_threshold:
            results['score'] += 0.4
            results['indicators'].append(f'Response timeout: {timing.total_time:.2f}s')
        elif timing.total_time > 5.0:  # 5초 이상
            results['score'] += 0.2
            results['indicators'].append(f'Slow response: {timing.total_time:.2f}s')

        # 3. 베이스라인과 비교
        if baseline:
            time_diff = abs(timing.total_time - baseline.total_time)
            if time_diff > 2.0:  # 2초 이상 차이
                results['score'] += 0.3
                results['anomalies'].append(f'Timing anomaly: {time_diff:.2f}s difference')

        # 4. 연결 시간 분석
        if timing.connect_time > 3.0:  # 3초 이상 연결 시간
            results['score'] += 0.2
            results['indicators'].append(f'Connection delay: {timing.connect_time:.2f}s')

        return results

    def detect_port_scan_timing(self, payloads_timing: List[Tuple[str, TimingData]]) -> Dict[str, Any]:
        """포트 스캔 타이밍 패턴 탐지"""
        if len(payloads_timing) < 3:
            return {'score': 0.0, 'pattern': None}

        # 포트별 응답 시간 분석
        port_times = {}
        for payload, timing in payloads_timing:
            parsed = urlparse(payload)
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            port_times[port] = timing.total_time

        if len(port_times) < 3:
            return {'score': 0.0, 'pattern': None}

        # 시간 편차 분석
        times = list(port_times.values())
        std_dev = statistics.stdev(times) if len(times) > 1 else 0
        mean_time = statistics.mean(times)

        score = 0.0
        if std_dev > 1.0:  # 1초 이상 편차
            score += 0.4
        if mean_time > 5.0:  # 평균 5초 이상
            score += 0.3

        return {
            'score': min(score, 1.0),
            'pattern': 'port_scan_timing',
            'statistics': {
                'mean_time': mean_time,
                'std_deviation': std_dev,
                'port_count': len(port_times)
            }
        }


class ResponsePatternDetector:
    """2계층: 응답 패턴 분석"""

    def __init__(self):
        self.error_patterns = [
            r'connection refused',
            r'network unreachable',
            r'host not found',
            r'timeout',
            r'curl_exec\(\)',
            r'file_get_contents\(\)',
            r'failed to open stream',
            r'java\.net\.ConnectException',
            r'requests\.exceptions',
            r'urllib\.error'
        ]

        self.success_indicators = [
            r'<html',
            r'<!DOCTYPE',
            r'HTTP/1\.[01]',
            r'Server:',
            r'Content-Type:',
            r'Set-Cookie:'
        ]

    def analyze_response_patterns(self, payload: str, response: Dict[str, Any]) -> Dict[str, Any]:
        """응답 패턴 분석"""
        results = {
            'score': 0.0,
            'indicators': [],
            'error_signals': [],
            'success_signals': []
        }

        content = response.get('content', '')
        status_code = response.get('status_code', 0)
        headers = response.get('headers', {})

        # 1. 상태 코드 분석
        if status_code == 0:
            results['score'] += 0.4
            results['error_signals'].append('No HTTP response')
        elif 200 <= status_code < 300:
            results['score'] += 0.3
            results['success_signals'].append(f'HTTP {status_code}')
        elif status_code in [403, 404, 500, 502, 503]:
            results['score'] += 0.2
            results['indicators'].append(f'HTTP {status_code} error')

        # 2. 에러 메시지 패턴 매칭
        for pattern in self.error_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                results['score'] += 0.3
                results['error_signals'].append(f'Error pattern: {pattern}')

        # 3. 성공 지표 패턴 매칭
        for pattern in self.success_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                results['score'] += 0.2
                results['success_signals'].append(f'Success pattern: {pattern}')

        # 4. 컨텐츠 길이 분석
        content_length = len(content)
        if content_length == 0:
            results['score'] += 0.2
            results['indicators'].append('Empty response')
        elif content_length > 10000:  # 10KB 이상
            results['score'] += 0.1
            results['indicators'].append(f'Large response: {content_length} bytes')

        # 5. 헤더 분석
        server_header = headers.get('server', '').lower()
        if any(server in server_header for server in ['apache', 'nginx', 'iis']):
            results['score'] += 0.1
            results['success_signals'].append(f'Server header: {server_header}')

        return results

    def detect_reflection_patterns(self, payload: str, response: Dict[str, Any]) -> Dict[str, Any]:
        """페이로드 반사 패턴 탐지"""
        content = response.get('content', '')
        
        # 페이로드의 주요 부분이 응답에 반사되는지 확인
        parsed = urlparse(payload)
        domain = parsed.netloc
        path = parsed.path
        
        reflection_score = 0.0
        reflected_parts = []
        
        if domain and domain in content:
            reflection_score += 0.3
            reflected_parts.append(f'domain: {domain}')
            
        if path and len(path) > 1 and path in content:
            reflection_score += 0.2
            reflected_parts.append(f'path: {path}')
            
        return {
            'score': reflection_score,
            'reflected_parts': reflected_parts
        }


class OOBDetector:
    """3계층: Out-of-Band 탐지"""

    def __init__(self, collaborator_domain: str = 'ssrf-test.local'):
        self.collaborator_domain = collaborator_domain
        self.dns_queries = []
        self.http_requests = []

    def generate_oob_payload(self, session_id: str, payload_type: str = 'dns') -> str:
        """OOB 페이로드 생성"""
        timestamp = int(time.time())
        
        if payload_type == 'dns':
            subdomain = f"{session_id}-{timestamp}"
            return f"http://{subdomain}.{self.collaborator_domain}/"
        elif payload_type == 'http':
            return f"http://{self.collaborator_domain}/{session_id}-{timestamp}"
        
        return f"http://{self.collaborator_domain}/"

    def check_oob_interactions(self, session_id: str, timeout: int = 10) -> Dict[str, Any]:
        """OOB 인터랙션 확인"""
        # 실제 구현에서는 DNS 서버/HTTP 서버 로그 확인
        # 여기서는 시뮬레이션
        
        time.sleep(timeout)
        
        # 예시: DNS/HTTP 로그에서 session_id 찾기
        dns_hits = self._check_dns_logs(session_id)
        http_hits = self._check_http_logs(session_id)
        
        total_hits = len(dns_hits) + len(http_hits)
        
        return {
            'oob_detected': total_hits > 0,
            'dns_hits': dns_hits,
            'http_hits': http_hits,
            'total_interactions': total_hits,
            'confidence': min(total_hits * 0.4, 1.0)
        }

    def _check_dns_logs(self, session_id: str) -> List[Dict[str, Any]]:
        """DNS 로그 확인 (시뮬레이션)"""
        # 실제 구현에서는 DNS 서버 로그 파싱
        import random
        if random.random() < 0.3:  # 30% 확률로 시뮬레이션
            return [
                {
                    'timestamp': time.time(),
                    'query': f"{session_id}-{int(time.time())}.{self.collaborator_domain}",
                    'source_ip': '192.168.1.100',
                    'query_type': 'A'
                }
            ]
        return []

    def _check_http_logs(self, session_id: str) -> List[Dict[str, Any]]:
        """HTTP 로그 확인 (시뮬레이션)"""
        # 실제 구현에서는 HTTP 서버 로그 파싱
        import random
        if random.random() < 0.2:  # 20% 확률로 시뮬레이션
            return [
                {
                    'timestamp': time.time(),
                    'path': f"/{session_id}-{int(time.time())}",
                    'source_ip': '10.0.0.50',
                    'user_agent': 'Internal-Service/1.0',
                    'method': 'GET'
                }
            ]
        return []


class ContextAnalyzer:
    """4계층: 컨텍스트 기반 분석"""

    def __init__(self):
        self.risk_multipliers = {
            'api': 1.3,
            'admin': 1.5,
            'webhook': 1.4,
            'proxy': 1.6,
            'file_upload': 1.2,
            'general': 1.0
        }

        self.environment_indicators = {
            'cloud': ['aws', 'azure', 'gcp', 'cloud', 'ec2', 'lambda'],
            'internal': ['internal', 'localhost', '127.0.0.1', '192.168', '10.'],
            'production': ['prod', 'production', 'live', 'api.'],
            'development': ['dev', 'test', 'staging', 'debug']
        }

    def analyze_context(self, target_info: Dict[str, Any], payload: str, detection_results: Dict[str, Any]) -> Dict[str, Any]:
        """컨텍스트 기반 분석"""
        results = {
            'risk_multiplier': 1.0,
            'environment_type': 'unknown',
            'context_indicators': [],
            'severity_adjustment': 0.0
        }

        # 1. 엔드포인트 타입 분석
        endpoint_type = target_info.get('endpoint_type', 'general')
        results['risk_multiplier'] = self.risk_multipliers.get(endpoint_type, 1.0)
        results['context_indicators'].append(f'Endpoint type: {endpoint_type}')

        # 2. 환경 타입 분석
        target_url = target_info.get('url', '')
        environment = self._detect_environment(target_url, payload)
        results['environment_type'] = environment
        
        # 환경별 위험도 조정
        if environment == 'production':
            results['severity_adjustment'] += 0.3
        elif environment == 'cloud':
            results['severity_adjustment'] += 0.4
        elif environment == 'internal':
            results['severity_adjustment'] += 0.2

        # 3. 페이로드 위험도 분석
        payload_risk = self._analyze_payload_risk(payload)
        results['severity_adjustment'] += payload_risk

        # 4. 탐지 결과 컨텍스트 분석
        if detection_results.get('multiple_layers_triggered', 0) >= 3:
            results['severity_adjustment'] += 0.2
            results['context_indicators'].append('Multiple detection layers triggered')

        return results

    def _detect_environment(self, target_url: str, payload: str) -> str:
        """환경 타입 탐지"""
        combined_text = f"{target_url} {payload}".lower()
        
        for env_type, indicators in self.environment_indicators.items():
            for indicator in indicators:
                if indicator in combined_text:
                    return env_type
        
        return 'unknown'

    def _analyze_payload_risk(self, payload: str) -> float:
        """페이로드 위험도 분석"""
        risk_score = 0.0
        
        # 프로토콜 위험도
        if payload.startswith('file://'):
            risk_score += 0.4
        elif payload.startswith('gopher://'):
            risk_score += 0.3
        elif any(payload.startswith(p) for p in ['dict://', 'ldap://', 'ftp://']):
            risk_score += 0.2
        
        # 메타데이터 서비스
        if '169.254.169.254' in payload:
            risk_score += 0.4
        elif 'metadata.google.internal' in payload:
            risk_score += 0.4
        
        # 내부 네트워크
        if any(ip in payload for ip in ['127.0.0.1', 'localhost', '192.168.', '10.']):
            risk_score += 0.2
        
        return min(risk_score, 0.5)


class MultiLayerSSRFDetector:
    """멀티레이어 SSRF 탐지 시스템"""

    def __init__(self, collaborator_domain: str = 'ssrf-test.local'):
        self.timing_detector = TimingDetector()
        self.pattern_detector = ResponsePatternDetector()
        self.oob_detector = OOBDetector(collaborator_domain)
        self.context_analyzer = ContextAnalyzer()
        
        # 탐지 임계값
        self.detection_threshold = 0.6  # 60% 이상에서 SSRF로 판단
        self.high_confidence_threshold = 0.8  # 80% 이상에서 고신뢰도

    async def detect_ssrf(self, target_info: Dict[str, Any], payload: str, 
                         response: Dict[str, Any], timing: Optional[TimingData] = None) -> Dict[str, Any]:
        """종합 SSRF 탐지"""
        
        # 각 계층별 탐지 수행
        layer_results = {}
        
        # 1계층: 타이밍 분석
        if timing:
            timing_result = self.timing_detector.analyze_timing_patterns(payload, timing)
            layer_results['timing'] = timing_result['score']
        else:
            layer_results['timing'] = 0.0
        
        # 2계층: 응답 패턴 분석
        pattern_result = self.pattern_detector.analyze_response_patterns(payload, response)
        layer_results['response_pattern'] = pattern_result['score']
        
        # 반사 패턴 추가 분석
        reflection_result = self.pattern_detector.detect_reflection_patterns(payload, response)
        layer_results['reflection'] = reflection_result['score']
        
        # 3계층: OOB 탐지 (시뮬레이션)
        oob_result = self.oob_detector.check_oob_interactions('test-session', timeout=2)
        layer_results['oob'] = oob_result['confidence']
        
        # 4계층: 컨텍스트 분석
        context_result = self.context_analyzer.analyze_context(
            target_info, payload, {'multiple_layers_triggered': sum(1 for score in layer_results.values() if score > 0.3)}
        )
        
        # 종합 신뢰도 계산
        base_confidence = self._calculate_confidence(layer_results)
        adjusted_confidence = base_confidence * context_result['risk_multiplier'] + context_result['severity_adjustment']
        final_confidence = min(max(adjusted_confidence, 0.0), 1.0)
        
        # SSRF 탐지 여부 결정
        is_vulnerable = final_confidence >= self.detection_threshold
        
        # 위험 레벨 결정
        if final_confidence >= self.high_confidence_threshold:
            risk_level = 'high'
        elif final_confidence >= self.detection_threshold:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        # 증거 수집
        evidence = self._collect_evidence(layer_results, pattern_result, timing_result if timing else None, oob_result)
        
        # 취약점 타입 결정
        vulnerability_type = self._determine_vulnerability_type(layer_results, payload)
        
        return {
            'is_vulnerable': is_vulnerable,
            'confidence': final_confidence,
            'vulnerability_type': vulnerability_type,
            'risk_level': risk_level,
            'detection_layers': layer_results,
            'evidence': evidence,
            'context_analysis': context_result,
            'recommended_actions': self._generate_recommendations(risk_level, vulnerability_type)
        }

    def _calculate_confidence(self, layer_results: Dict[str, float]) -> float:
        """계층별 결과를 기반으로 신뢰도 계산"""
        # 가중치 적용
        weights = {
            'timing': 0.25,
            'response_pattern': 0.35,
            'reflection': 0.15,
            'oob': 0.25
        }
        
        weighted_sum = 0.0
        for layer, score in layer_results.items():
            weight = weights.get(layer, 0.0)
            weighted_sum += score * weight
        
        return weighted_sum

    def _collect_evidence(self, layer_results: Dict[str, float], pattern_result: Dict[str, Any],
                         timing_result: Optional[Dict[str, Any]], oob_result: Dict[str, Any]) -> List[str]:
        """증거 수집"""
        evidence = []
        
        # 타이밍 증거
        if timing_result and layer_results.get('timing', 0) > 0.3:
            evidence.extend(timing_result.get('indicators', []))
        
        # 응답 패턴 증거
        if layer_results.get('response_pattern', 0) > 0.3:
            evidence.extend(pattern_result.get('error_signals', []))
            evidence.extend(pattern_result.get('success_signals', []))
        
        # OOB 증거
        if oob_result.get('oob_detected', False):
            evidence.append(f"OOB interaction detected: {oob_result['total_interactions']} hits")
        
        return evidence[:10]  # 최대 10개만

    def _determine_vulnerability_type(self, layer_results: Dict[str, float], payload: str) -> str:
        """취약점 타입 결정"""
        if layer_results.get('oob', 0) > 0.5:
            return 'blind_ssrf'
        elif layer_results.get('response_pattern', 0) > 0.5:
            if 'file://' in payload:
                return 'file_disclosure_ssrf'
            elif any(proto in payload for proto in ['gopher://', 'dict://', 'ldap://']):
                return 'protocol_smuggling_ssrf'
            else:
                return 'response_based_ssrf'
        elif layer_results.get('timing', 0) > 0.5:
            return 'timing_based_ssrf'
        else:
            return 'potential_ssrf'

    def _generate_recommendations(self, risk_level: str, vulnerability_type: str) -> List[str]:
        """권장 사항 생성"""
        recommendations = []
        
        if risk_level == 'high':
            recommendations.extend([
                'Immediate patching required',
                'Block internal network access',
                'Implement strict URL validation'
            ])
        elif risk_level == 'medium':
            recommendations.extend([
                'Implement URL whitelist',
                'Add network segmentation',
                'Monitor for exploitation attempts'
            ])
        
        if vulnerability_type == 'blind_ssrf':
            recommendations.append('Monitor DNS/HTTP logs for OOB interactions')
        elif 'file' in vulnerability_type:
            recommendations.append('Restrict file protocol access')
        
        return recommendations


def main():
    """테스트 실행"""
    detector = MultiLayerSSRFDetector()
    
    # 샘플 데이터
    target_info = {
        'url': 'https://api.example.com/fetch',
        'endpoint_type': 'api',
        'method': 'POST'
    }
    
    payload = 'http://127.0.0.1:8080/admin'
    
    response = {
        'status_code': 200,
        'content': '<html><body>Internal Admin Panel</body></html>',
        'headers': {'server': 'Apache/2.4.41', 'content-type': 'text/html'}
    }
    
    timing = TimingData(
        total_time=2.5,
        dns_time=150.0,
        connect_time=1.2,
        response_time=1.3
    )
    
    print("=== 멀티레이어 SSRF 탐지 시스템 테스트 ===")
    
    import asyncio
    result = asyncio.run(detector.detect_ssrf(target_info, payload, response, timing))
    
    print(f"\nSSRF 탐지 결과:")
    print(f"  취약: {result['is_vulnerable']}")
    print(f"  신뢰도: {result['confidence']:.2%}")
    print(f"  취약점 타입: {result['vulnerability_type']}")
    print(f"  위험 레벨: {result['risk_level']}")
    
    print(f"\n계층별 탐지 결과:")
    for layer, score in result['detection_layers'].items():
        print(f"  {layer}: {score:.2%}")
    
    print(f"\n증거:")
    for evidence in result['evidence']:
        print(f"  - {evidence}")
    
    print(f"\n권장 사항:")
    for rec in result['recommended_actions']:
        print(f"  - {rec}")


if __name__ == "__main__":
    main()
