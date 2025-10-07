"""
OOB (Out-of-Band) Collaborator 서버
블라인드 SSRF 탐지를 위한 DNS/HTTP 서버
"""

import time
import json
import uuid
import threading
import hashlib
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import socket
import struct


@dataclass
class OOBInteraction:
    """바이너리 인터랙션 데이터"""
    timestamp: float
    interaction_type: str  # 'dns' or 'http'
    source_ip: str
    payload_id: str
    session_id: str
    full_domain: str
    raw_data: str
    confidence: float


@dataclass
class CollaboratorSession:
    """콜라보레이터 세션"""
    session_id: str
    name: str
    created_at: float
    last_activity: float
    interactions: List[OOBInteraction]
    active: bool


class DNSCollaborator:
    """DNS Collaborator 서버"""
    
    def __init__(self, domain: str, port: int = 5353):
        self.domain = domain
        self.port = port
        self.running = False
        self.interactions = []
        self.server_thread = None
        
    def start_server(self):
        """시뮬레이션된 DNS 서버 시작"""
        self.running = True
        print(f"[+] DNS Collaborator 시작: {self.domain}:{self.port}")
        print("    실제 구현에서는 UDP DNS 서버가 시작됩니다.")
        
    def stop_server(self):
        """DNS 서버 중단"""
        self.running = False
        print("[+] DNS Collaborator 중단")
        
    def simulate_dns_query(self, full_domain: str, source_ip: str, session_id: str) -> OOBInteraction:
        """시뮬레이션된 DNS 쿼리 처리"""
        payload_id = full_domain.split('.')[0] if '.' in full_domain else full_domain
        
        interaction = OOBInteraction(
            timestamp=time.time(),
            interaction_type='dns',
            source_ip=source_ip,
            payload_id=payload_id,
            session_id=session_id,
            full_domain=full_domain,
            raw_data=f"DNS A {full_domain}",
            confidence=0.9
        )
        
        self.interactions.append(interaction)
        print(f"[DNS] 쿼리 수신: {full_domain} from {source_ip}")
        return interaction
        
    def get_interactions_for_session(self, session_id: str) -> List[OOBInteraction]:
        """세션별 DNS 인터랙션 조회"""
        return [i for i in self.interactions if i.session_id == session_id]


class HTTPCollaborator:
    """HTTP Collaborator 서버"""
    
    def __init__(self, domain: str, port: int = 8888):
        self.domain = domain
        self.port = port
        self.running = False
        self.interactions = []
        self.server_thread = None
        
    def start_server(self):
        """시뮬레이션된 HTTP 서버 시작"""
        self.running = True
        print(f"[+] HTTP Collaborator 시작: {self.domain}:{self.port}")
        print("    실제 구현에서는 HTTP 서버가 시작됩니다.")
        
    def stop_server(self):
        """HTTP 서버 중단"""
        self.running = False
        print("[+] HTTP Collaborator 중단")
        
    def simulate_http_request(self, path: str, source_ip: str, session_id: str, 
                            method: str = 'GET', headers: Dict[str, str] = None) -> OOBInteraction:
        """시뮬레이션된 HTTP 요청 처리"""
        headers = headers or {}
        payload_id = path.strip('/').split('/')[0] if '/' in path else path
        
        interaction = OOBInteraction(
            timestamp=time.time(),
            interaction_type='http',
            source_ip=source_ip,
            payload_id=payload_id,
            session_id=session_id,
            full_domain=f"{self.domain}{path}",
            raw_data=f"{method} {path} HTTP/1.1\nHost: {self.domain}\nUser-Agent: {headers.get('User-Agent', 'Unknown')}",
            confidence=0.8
        )
        
        self.interactions.append(interaction)
        print(f"[HTTP] 요청 수신: {method} {path} from {source_ip}")
        return interaction
        
    def get_interactions_for_session(self, session_id: str) -> List[OOBInteraction]:
        """세션별 HTTP 인터랙션 조회"""
        return [i for i in self.interactions if i.session_id == session_id]


class OOBCollaborator:
    """메인 OOB Collaborator 클래스"""
    
    def __init__(self, domain: str = 'ssrf-test.local'):
        self.domain = domain
        self.dns_server = DNSCollaborator(domain)
        self.http_server = HTTPCollaborator(domain)
        self.sessions: Dict[str, CollaboratorSession] = {}
        self.running = False
        
    def start(self):
        """Collaborator 서비스 시작"""
        print(f"=== OOB Collaborator 시작: {self.domain} ===")
        self.dns_server.start_server()
        self.http_server.start_server()
        self.running = True
        print("[+] Collaborator 준비 완료")
        
    def stop(self):
        """Collaborator 서비스 중단"""
        self.dns_server.stop_server()
        self.http_server.stop_server()
        self.running = False
        print("[+] OOB Collaborator 중단")
        
    def create_session(self, name: str) -> str:
        """새로운 세션 생성"""
        session_id = str(uuid.uuid4())[:8]
        
        session = CollaboratorSession(
            session_id=session_id,
            name=name,
            created_at=time.time(),
            last_activity=time.time(),
            interactions=[],
            active=True
        )
        
        self.sessions[session_id] = session
        print(f"[+] 세션 생성: {session_id} ({name})")
        return session_id
        
    def generate_payload(self, session_id: str, payload_type: str = 'dns') -> Dict[str, str]:
        """세션별 페이로드 생성"""
        if session_id not in self.sessions:
            raise ValueError(f"Session not found: {session_id}")
            
        timestamp = int(time.time())
        payload_id = f"{session_id}-{timestamp}"
        
        if payload_type == 'dns':
            subdomain = f"{payload_id}.{self.domain}"
            full_payload = f"http://{subdomain}/"
            
            return {
                'payload_id': payload_id,
                'subdomain': subdomain,
                'full_payload': full_payload,
                'type': 'dns'
            }
            
        elif payload_type == 'http':
            path = f"/{payload_id}"
            full_payload = f"http://{self.domain}{path}"
            
            return {
                'payload_id': payload_id,
                'path': path,
                'full_payload': full_payload,
                'type': 'http'
            }
            
        else:
            raise ValueError(f"Unknown payload type: {payload_type}")
            
    def detect_ssrf(self, session_id: str, timeout: int = 10) -> Dict[str, Any]:
        """SSRF 인터랙션 탐지"""
        if session_id not in self.sessions:
            return {
                'ssrf_detected': False,
                'confidence': 0.0,
                'error': f'Session not found: {session_id}'
            }
            
        session = self.sessions[session_id]
        start_time = time.time()
        
        # 시뮬레이션: 일정 확률로 인터랙션 발생
        import random
        if random.random() < 0.4:  # 40% 확률
            # DNS 인터랙션 시뮬레이션
            dns_interaction = self.dns_server.simulate_dns_query(
                f"{session_id}-{int(time.time())}.{self.domain}",
                f"192.168.1.{random.randint(10, 254)}",
                session_id
            )
            session.interactions.append(dns_interaction)
            
        if random.random() < 0.3:  # 30% 확률
            # HTTP 인터랙션 시뮬레이션
            http_interaction = self.http_server.simulate_http_request(
                f"/{session_id}-{int(time.time())}",
                f"10.0.0.{random.randint(10, 254)}",
                session_id,
                headers={'User-Agent': 'Internal-Service/1.0'}
            )
            session.interactions.append(http_interaction)
            
        # 세션 인터랙션 분석
        dns_interactions = [i for i in session.interactions if i.interaction_type == 'dns']
        http_interactions = [i for i in session.interactions if i.interaction_type == 'http']
        
        total_interactions = len(dns_interactions) + len(http_interactions)
        
        # 신뢰도 계산
        confidence = 0.0
        if total_interactions > 0:
            # 기본 신뢰도
            confidence = min(total_interactions * 0.3, 0.9)
            
            # DNS 인터랙션이 있으면 더 높은 신뢰도
            if dns_interactions:
                confidence += 0.2
                
            # 여러 타입의 인터랙션이 있으면 더 높은 신뢰도
            if dns_interactions and http_interactions:
                confidence += 0.3
                
        confidence = min(confidence, 1.0)
        
        # 세션 업데이트
        session.last_activity = time.time()
        
        # 분석 결과 생성
        analysis = self._generate_interaction_analysis(dns_interactions, http_interactions)
        
        return {
            'ssrf_detected': total_interactions > 0,
            'confidence': confidence,
            'total_interactions': total_interactions,
            'dns_interactions': len(dns_interactions),
            'http_interactions': len(http_interactions),
            'analysis': analysis,
            'session_info': {
                'session_id': session_id,
                'name': session.name,
                'duration': time.time() - session.created_at
            }
        }
        
    def _generate_interaction_analysis(self, dns_interactions: List[OOBInteraction], 
                                     http_interactions: List[OOBInteraction]) -> List[str]:
        """인터랙션 분석 결과 생성"""
        analysis = []
        
        if dns_interactions:
            unique_sources = set(i.source_ip for i in dns_interactions)
            analysis.append(f"DNS queries from {len(unique_sources)} unique source(s)")
            
            for interaction in dns_interactions[:3]:  # 최대 3개만 표시
                analysis.append(f"DNS: {interaction.full_domain} from {interaction.source_ip}")
                
        if http_interactions:
            unique_sources = set(i.source_ip for i in http_interactions)
            analysis.append(f"HTTP requests from {len(unique_sources)} unique source(s)")
            
            for interaction in http_interactions[:3]:  # 최대 3개만 표시
                analysis.append(f"HTTP: {interaction.full_domain} from {interaction.source_ip}")
                
        if not analysis:
            analysis.append("No OOB interactions detected")
            
        return analysis
        
    def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """세션 정보 조회"""
        if session_id not in self.sessions:
            return None
            
        session = self.sessions[session_id]
        return {
            'session_id': session.session_id,
            'name': session.name,
            'created_at': datetime.fromtimestamp(session.created_at).isoformat(),
            'last_activity': datetime.fromtimestamp(session.last_activity).isoformat(),
            'total_interactions': len(session.interactions),
            'dns_interactions': len([i for i in session.interactions if i.interaction_type == 'dns']),
            'http_interactions': len([i for i in session.interactions if i.interaction_type == 'http']),
            'active': session.active
        }
        
    def export_session_data(self, session_id: str) -> Optional[Dict[str, Any]]:
        """세션 데이터 내보내기"""
        if session_id not in self.sessions:
            return None
            
        session = self.sessions[session_id]
        return {
            'session': asdict(session),
            'interactions': [asdict(i) for i in session.interactions],
            'statistics': {
                'total_interactions': len(session.interactions),
                'dns_count': len([i for i in session.interactions if i.interaction_type == 'dns']),
                'http_count': len([i for i in session.interactions if i.interaction_type == 'http']),
                'unique_sources': len(set(i.source_ip for i in session.interactions)),
                'duration': time.time() - session.created_at
            }
        }
        
    def list_sessions(self) -> List[Dict[str, Any]]:
        """모든 세션 목록"""
        return [self.get_session_info(sid) for sid in self.sessions.keys()]
        
    def cleanup_old_sessions(self, max_age_hours: int = 24):
        """오래된 세션 정리"""
        current_time = time.time()
        max_age_seconds = max_age_hours * 3600
        
        to_remove = []
        for session_id, session in self.sessions.items():
            if current_time - session.created_at > max_age_seconds:
                to_remove.append(session_id)
                
        for session_id in to_remove:
            del self.sessions[session_id]
            print(f"[+] 오래된 세션 삭제: {session_id}")
            
        return len(to_remove)


def main():
    """테스트 실행"""
    collaborator = OOBCollaborator('ssrf-test.local')
    
    print("=== OOB Collaborator 테스트 ===")
    
    # Collaborator 시작
    collaborator.start()
    
    # 테스트 세션 생성
    session_id = collaborator.create_session("Test SSRF Session")
    
    # 페이로드 생성
    print("\n페이로드 생성:")
    dns_payload = collaborator.generate_payload(session_id, 'dns')
    print(f"  DNS: {dns_payload['full_payload']}")
    
    http_payload = collaborator.generate_payload(session_id, 'http')
    print(f"  HTTP: {http_payload['full_payload']}")
    
    # SSRF 탐지 시뮬레이션
    print("\nSSRF 탐지 시뮬레이션...")
    detection_result = collaborator.detect_ssrf(session_id, timeout=5)
    
    print(f"\n탐지 결과:")
    print(f"  SSRF 탐지: {detection_result['ssrf_detected']}")
    print(f"  신뢰도: {detection_result['confidence']:.2%}")
    print(f"  전체 인터랙션: {detection_result['total_interactions']}개")
    print(f"  DNS: {detection_result['dns_interactions']}개, HTTP: {detection_result['http_interactions']}개")
    
    print(f"\n분석:")
    for analysis in detection_result['analysis']:
        print(f"  - {analysis}")
    
    # 세션 정보
    session_info = collaborator.get_session_info(session_id)
    print(f"\n세션 정보:")
    print(f"  ID: {session_info['session_id']}")
    print(f"  이름: {session_info['name']}")
    print(f"  생성: {session_info['created_at']}")
    print(f"  마지막 활동: {session_info['last_activity']}")
    
    # Collaborator 중단
    collaborator.stop()


if __name__ == "__main__":
    main()
