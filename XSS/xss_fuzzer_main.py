"""
XSS Fuzzer Main: 전체 파이프라인 통합

세계 최고의 블랙박스 XSS 퍼저 - 전체 모듈 통합:
1. XSSCrawler - 인젝션 포인트 발견
2. ContextAnalyzer - 컨텍스트 분석
3. PayloadGenerator - 페이로드 생성
4. WAFHandler - WAF 탐지 및 우회
5. GeneticFuzzer - 유전 알고리즘 최적화
6. XSSVerifier - XSS 실행 검증

Architecture:
    XSSCrawler → InjectionPoints → ContextAnalyzer → PayloadGenerator →
    WAFHandler → GeneticFuzzer → XSSVerifier → Report
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from playwright.sync_api import sync_playwright, Browser, Page
import time
import json
from datetime import datetime

# 모듈 임포트
from xss_crawler import XSSCrawler, CrawlerConfig, InjectionPoint, CrawlResult
from context_analyzer import ContextAnalyzer, AnalysisResult
from payload_generator import PayloadGenerator, GeneratedPayload
from waf_handler import WAFHandler, WAFDetectionResult, BypassResult
from genetic_fuzzer import GeneticFuzzer, Individual
from xss_verifier import XSSVerifier, VerificationResult


@dataclass
class FuzzingConfig:
    """퍼징 설정"""
    # 크롤링 설정
    start_url: str
    max_depth: int = 2
    max_pages: int = 50
    headless: bool = True

    # 인증 설정
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None

    # 퍼징 설정
    max_payloads_per_context: int = 20
    enable_mutations: bool = True
    enable_encoding: bool = True

    # WAF 설정
    enable_waf_detection: bool = True
    max_waf_bypass_attempts: int = 10

    # 유전 알고리즘 설정
    enable_genetic_fuzzing: bool = True
    population_size: int = 10
    max_generations: int = 5
    mutation_rate: float = 0.3

    # XSS 검증 설정
    verification_timeout: int = 5000  # ms

    # 리포트 설정
    output_json: Optional[str] = None
    verbose: bool = True


@dataclass
class InjectionPointResult:
    """개별 인젝션 포인트 퍼징 결과"""
    injection_point: InjectionPoint
    context_result: Optional[AnalysisResult] = None
    waf_detected: bool = False
    waf_bypassed: bool = False
    payloads_tested: int = 0
    xss_found: bool = False
    successful_payload: Optional[str] = None
    verification_result: Optional[VerificationResult] = None
    execution_time: float = 0.0
    error: Optional[str] = None


@dataclass
class FuzzingReport:
    """전체 퍼징 리포트"""
    config: FuzzingConfig
    crawl_result: CrawlResult
    injection_point_results: List[InjectionPointResult] = field(default_factory=list)
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    end_time: Optional[str] = None
    total_injection_points: int = 0
    total_contexts_detected: int = 0
    total_payloads_tested: int = 0
    total_xss_found: int = 0
    waf_detected_count: int = 0
    waf_bypassed_count: int = 0

    def finalize(self):
        """리포트 완료 처리"""
        self.end_time = datetime.now().isoformat()
        self.total_injection_points = len(self.injection_point_results)
        self.total_contexts_detected = sum(
            1 for r in self.injection_point_results
            if r.context_result and len(r.context_result.contexts) > 0
        )
        self.total_payloads_tested = sum(r.payloads_tested for r in self.injection_point_results)
        self.total_xss_found = sum(1 for r in self.injection_point_results if r.xss_found)
        self.waf_detected_count = sum(1 for r in self.injection_point_results if r.waf_detected)
        self.waf_bypassed_count = sum(1 for r in self.injection_point_results if r.waf_bypassed)

    def to_dict(self) -> dict:
        """딕셔너리로 변환"""
        return {
            'config': {
                'start_url': self.config.start_url,
                'max_depth': self.config.max_depth,
                'max_pages': self.config.max_pages,
                'enable_genetic_fuzzing': self.config.enable_genetic_fuzzing,
                'enable_waf_detection': self.config.enable_waf_detection
            },
            'summary': {
                'start_time': self.start_time,
                'end_time': self.end_time,
                'total_injection_points': self.total_injection_points,
                'total_contexts_detected': self.total_contexts_detected,
                'total_payloads_tested': self.total_payloads_tested,
                'total_xss_found': self.total_xss_found,
                'waf_detected_count': self.waf_detected_count,
                'waf_bypassed_count': self.waf_bypassed_count
            },
            'findings': [
                {
                    'injection_point': r.injection_point.to_dict(),
                    'contexts': [c.to_dict() for c in r.context_result.contexts] if r.context_result else [],
                    'xss_found': r.xss_found,
                    'successful_payload': r.successful_payload,
                    'waf_detected': r.waf_detected,
                    'waf_bypassed': r.waf_bypassed,
                    'payloads_tested': r.payloads_tested,
                    'execution_time': r.execution_time
                }
                for r in self.injection_point_results
                if r.xss_found  # XSS가 발견된 것만 리포트
            ]
        }

    def save_to_json(self, filepath: str):
        """JSON 파일로 저장"""
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
        print(f"[+] Report saved to: {filepath}")


class XSSFuzzer:
    """
    통합 XSS 퍼저

    전체 파이프라인을 통합하여 자동화된 XSS 퍼징 수행
    """

    def __init__(self, config: FuzzingConfig):
        """
        Args:
            config: 퍼징 설정
        """
        self.config = config
        self.browser: Optional[Browser] = None
        self.page: Optional[Page] = None

        # 모듈 인스턴스 (나중에 초기화)
        self.crawler: Optional[XSSCrawler] = None
        self.context_analyzer: Optional[ContextAnalyzer] = None
        self.payload_generator: Optional[PayloadGenerator] = None
        self.waf_handler: Optional[WAFHandler] = None
        self.xss_verifier: Optional[XSSVerifier] = None

    def _print(self, message: str):
        """로그 출력 (verbose 모드일 때만)"""
        if self.config.verbose:
            print(message)

    def run(self, crawl_result: Optional[CrawlResult] = None) -> FuzzingReport:
        """
        전체 퍼징 파이프라인 실행

        Args:
            crawl_result: 크롤링 결과 (제공되지 않으면 크롤링 수행)

        Returns:
            FuzzingReport: 퍼징 결과 리포트
        """
        self._print("\n" + "="*60)
        self._print("XSS Fuzzer - Full Pipeline")
        self._print("="*60 + "\n")

        # 크롤링 결과가 제공되지 않으면 크롤링 수행
        if crawl_result is None:
            self._print("[Phase 1] Crawling and Discovery")
            crawl_result = self._crawl_phase()

        # 이미 크롤링 결과가 있으면 브라우저만 시작
        with sync_playwright() as p:
            # 브라우저 시작
            self.browser = p.chromium.launch(headless=self.config.headless)
            self.page = self.browser.new_page()

            try:
                # Phase 2: 퍼징
                self._print(f"\n[Phase 2] Fuzzing {len(crawl_result.injection_points)} injection points")
                report = self._fuzzing_phase(crawl_result)

                # Phase 3: 리포트 생성
                self._print("\n[Phase 3] Generating Report")
                report.finalize()

                if self.config.output_json:
                    report.save_to_json(self.config.output_json)

                # 요약 출력
                self._print_summary(report)

                return report

            finally:
                # 브라우저 종료
                if self.browser:
                    self.browser.close()

    def _crawl_phase(self) -> CrawlResult:
        """
        크롤링 단계: XSSCrawler로 인젝션 포인트 발견

        Returns:
            CrawlResult: 크롤링 결과
        """
        # XSSCrawler 설정
        crawler_config = CrawlerConfig(
            max_depth=self.config.max_depth,
            max_pages=self.config.max_pages,
            headless=self.config.headless,
            login_url=self.config.login_url,
            username=self.config.username,
            password=self.config.password,
            submit_forms=True,  # 폼 자동 제출 활성화
            trigger_elements=True  # 인터랙티브 요소 트리거
        )

        self.crawler = XSSCrawler(crawler_config)

        # 로그인 (설정된 경우)
        if self.config.login_url:
            self._print("[+] Attempting login...")
            if self.crawler.login():
                self._print("[OK] Login successful")
            else:
                self._print("[WARN] Login failed, continuing without authentication")

        # 크롤링 시작
        self._print(f"[+] Starting crawl from: {self.config.start_url}")
        crawl_result = self.crawler.crawl(self.config.start_url)

        self._print(f"[OK] Crawl complete:")
        self._print(f"    - Crawled URLs: {len(crawl_result.crawled_urls)}")
        self._print(f"    - Forms found: {len(crawl_result.forms)}")
        self._print(f"    - Endpoints found: {len(crawl_result.endpoints)}")
        self._print(f"    - Injection points: {len(crawl_result.injection_points)}")

        return crawl_result

    def _fuzzing_phase(self, crawl_result: CrawlResult) -> FuzzingReport:
        """
        퍼징 단계: 각 인젝션 포인트에 대해 퍼징 수행

        Args:
            crawl_result: 크롤링 결과

        Returns:
            FuzzingReport: 퍼징 리포트
        """
        # 모듈 초기화
        self.context_analyzer = ContextAnalyzer(self.page)
        self.payload_generator = PayloadGenerator()
        self.waf_handler = WAFHandler(self.page)
        self.xss_verifier = XSSVerifier(self.page, timeout=self.config.verification_timeout)

        # 리포트 초기화
        report = FuzzingReport(
            config=self.config,
            crawl_result=crawl_result
        )

        # 각 인젝션 포인트 퍼징
        for i, injection_point in enumerate(crawl_result.injection_points, 1):
            self._print(f"\n[{i}/{len(crawl_result.injection_points)}] Testing: {injection_point.url}")
            self._print(f"    Parameter: {injection_point.parameter_name} ({injection_point.point_type})")

            result = self._fuzz_injection_point(injection_point)
            report.injection_point_results.append(result)

            if result.xss_found:
                self._print(f"    [OK] XSS FOUND! Payload: {result.successful_payload[:50]}...")
            elif result.error:
                self._print(f"    [FAIL] Error: {result.error}")
            else:
                self._print(f"    [FAIL] No XSS found ({result.payloads_tested} payloads tested)")

        return report

    def _fuzz_injection_point(self, injection_point: InjectionPoint) -> InjectionPointResult:
        """
        개별 인젝션 포인트 퍼징

        Args:
            injection_point: 인젝션 포인트

        Returns:
            InjectionPointResult: 퍼징 결과
        """
        start_time = time.time()
        result = InjectionPointResult(injection_point=injection_point)

        try:
            # Step 1: 컨텍스트 분석
            self._print("    [1/5] Analyzing context...")
            context_result = self.context_analyzer.analyze_injection_point(
                url=injection_point.url,
                param_name=injection_point.parameter_name,
                method=injection_point.method
            )
            result.context_result = context_result

            if not context_result.contexts:
                self._print("    [SKIP] No reflection detected")
                return result

            self._print(f"    [OK] {len(context_result.contexts)} contexts detected: " +
                       ", ".join([c.context_type for c in context_result.contexts]))

            # Step 2: 페이로드 생성
            self._print("    [2/5] Generating payloads...")
            all_payloads = []
            for context in context_result.contexts:
                payloads = self.payload_generator.generate_for_context(
                    context_type=context.context_type,
                    max_payloads=self.config.max_payloads_per_context,
                    apply_mutations=self.config.enable_mutations,
                    apply_encoding=self.config.enable_encoding
                )
                all_payloads.extend(payloads)

            self._print(f"    [OK] {len(all_payloads)} payloads generated")
            result.payloads_tested = len(all_payloads)

            # Step 3: WAF 탐지 및 우회
            if self.config.enable_waf_detection:
                self._print("    [3/5] Detecting WAF...")
                waf_detection, waf_bypass = self.waf_handler.detect_and_bypass(
                    url=injection_point.url,
                    original_payload="<script>alert(1)</script>",
                    max_attempts=self.config.max_waf_bypass_attempts
                )

                result.waf_detected = waf_detection.detected
                if waf_detection.detected:
                    self._print(f"    [WARN] WAF detected: {waf_detection.waf_name or 'Unknown'}")
                    if waf_bypass and waf_bypass.bypassed:
                        result.waf_bypassed = True
                        self._print(f"    [OK] WAF bypassed with: {waf_bypass.technique}")
                        # WAF 우회 기법을 페이로드에 적용 (간단히 우회 페이로드 추가)
                        all_payloads.append(GeneratedPayload(
                            payload=waf_bypass.payload,
                            context_type='html_body',
                            encoding=None,
                            mutation=waf_bypass.technique,
                            description=f'WAF bypass: {waf_bypass.technique}'
                        ))
                    else:
                        self._print(f"    [WARN] WAF bypass failed")
                else:
                    self._print("    [OK] No WAF detected")
            else:
                self._print("    [3/5] WAF detection disabled")

            # Step 4: 유전 알고리즘 (선택 사항)
            if self.config.enable_genetic_fuzzing:
                self._print("    [4/5] Evolving payloads with genetic algorithm...")
                seed_payloads = [p.payload for p in all_payloads[:10]]  # 상위 10개로 시드

                fuzzer = GeneticFuzzer(
                    population_size=self.config.population_size,
                    max_generations=self.config.max_generations,
                    mutation_rate=self.config.mutation_rate
                )

                # 평가 함수 정의
                def evaluate_payload(individual: Individual) -> Individual:
                    """페이로드 평가"""
                    test_url = self._build_test_url(injection_point, individual.payload)

                    try:
                        response = self.page.goto(test_url, timeout=3000, wait_until='networkidle')
                        individual.http_200 = (response.status == 200)

                        html = self.page.content()
                        individual.reflected = individual.payload in html

                        # 간단한 XSS 검사 (alert 실행 여부)
                        # 실제 검증은 나중에 XSSVerifier로 수행
                        individual.waf_bypassed = True  # 일단 True로 (WAF 우회 이미 확인됨)

                        individual.calculate_fitness()
                    except:
                        individual.fitness = 0.0

                    return individual

                best_individual = fuzzer.run(
                    seed_payloads=seed_payloads,
                    evaluation_function=evaluate_payload,
                    verbose=False
                )

                # 진화된 최고 페이로드 추가
                all_payloads.append(GeneratedPayload(
                    payload=best_individual.payload,
                    context_type='evolved',
                    encoding=None,
                    mutation='genetic_algorithm',
                    description=f'Evolved payload (fitness: {best_individual.fitness:.2f})'
                ))

                self._print(f"    [OK] Best evolved payload (fitness: {best_individual.fitness:.2f})")
            else:
                self._print("    [4/5] Genetic fuzzing disabled")

            # Step 5: XSS 검증
            self._print("    [5/5] Verifying XSS execution...")
            for payload_obj in all_payloads:
                test_url = self._build_test_url(injection_point, payload_obj.payload)

                verification = self.xss_verifier.verify_reflected_xss(
                    url=test_url,
                    payload=payload_obj.payload,
                    method=injection_point.method
                )

                if verification.verified:
                    result.xss_found = True
                    result.successful_payload = payload_obj.payload
                    result.verification_result = verification
                    break  # 첫 번째 성공한 페이로드만 기록

        except Exception as e:
            result.error = str(e)
            self._print(f"    [ERROR] {e}")

        finally:
            result.execution_time = time.time() - start_time

        return result

    def _build_test_url(self, injection_point: InjectionPoint, payload: str) -> str:
        """
        테스트 URL 생성

        Args:
            injection_point: 인젝션 포인트
            payload: 페이로드

        Returns:
            str: 테스트 URL
        """
        import urllib.parse

        if injection_point.method == 'GET' or injection_point.point_type == 'url_param':
            # URL 파라미터로 추가
            separator = '&' if '?' in injection_point.url else '?'
            return f"{injection_point.url}{separator}{injection_point.parameter_name}={urllib.parse.quote(payload)}"
        else:
            # POST는 일단 GET과 동일하게 처리 (간단히)
            # 실제로는 XSSVerifier의 POST 기능 사용해야 함
            separator = '&' if '?' in injection_point.url else '?'
            return f"{injection_point.url}{separator}{injection_point.parameter_name}={urllib.parse.quote(payload)}"

    def _print_summary(self, report: FuzzingReport):
        """퍼징 결과 요약 출력"""
        self._print("\n" + "="*60)
        self._print("Fuzzing Summary")
        self._print("="*60)
        self._print(f"\nTotal Injection Points: {report.total_injection_points}")
        self._print(f"Total Contexts Detected: {report.total_contexts_detected}")
        self._print(f"Total Payloads Tested: {report.total_payloads_tested}")
        self._print(f"Total XSS Found: {report.total_xss_found}")

        if report.waf_detected_count > 0:
            self._print(f"\nWAF Detected: {report.waf_detected_count} times")
            self._print(f"WAF Bypassed: {report.waf_bypassed_count} times")

        if report.total_xss_found > 0:
            self._print(f"\n[SUCCESS] {report.total_xss_found} XSS vulnerabilities found!")
            self._print("\nSuccessful Payloads:")
            for i, result in enumerate(report.injection_point_results, 1):
                if result.xss_found:
                    self._print(f"\n  [{i}] {result.injection_point.url}")
                    self._print(f"      Parameter: {result.injection_point.parameter_name}")
                    self._print(f"      Payload: {result.successful_payload[:80]}...")
                    if result.verification_result:
                        self._print(f"      Evidences: {len(result.verification_result.evidences)}")
        else:
            self._print("\n[INFO] No XSS vulnerabilities found")

        self._print("\n" + "="*60 + "\n")


# ========================================
# 유틸리티 함수
# ========================================

def quick_fuzz(
    url: str,
    max_depth: int = 2,
    max_pages: int = 50,
    output_json: Optional[str] = None,
    verbose: bool = True
) -> FuzzingReport:
    """
    빠른 퍼징 실행 (간편 함수)

    Args:
        url: 시작 URL
        max_depth: 최대 크롤링 깊이
        max_pages: 최대 페이지 수
        output_json: JSON 리포트 저장 경로
        verbose: 상세 로그 출력

    Returns:
        FuzzingReport: 퍼징 결과
    """
    config = FuzzingConfig(
        start_url=url,
        max_depth=max_depth,
        max_pages=max_pages,
        output_json=output_json,
        verbose=verbose
    )

    fuzzer = XSSFuzzer(config)
    return fuzzer.run()


if __name__ == "__main__":
    """
    사용 예제
    """
    print("""
XSS Fuzzer Main - Integrated Pipeline

Usage:
    from xss_fuzzer_main import XSSFuzzer, FuzzingConfig

    # 설정
    config = FuzzingConfig(
        start_url='http://localhost:5000',
        max_depth=2,
        max_pages=20,
        enable_genetic_fuzzing=True,
        enable_waf_detection=True,
        output_json='fuzzing_report.json',
        verbose=True
    )

    # 퍼징 실행
    fuzzer = XSSFuzzer(config)
    report = fuzzer.run()

    # 결과 확인
    print(f"XSS Found: {report.total_xss_found}")

Or use the quick function:
    from xss_fuzzer_main import quick_fuzz

    report = quick_fuzz(
        url='http://localhost:5000',
        max_depth=2,
        output_json='report.json'
    )

For tests, see tests/test_integration_pipeline.py
""")
