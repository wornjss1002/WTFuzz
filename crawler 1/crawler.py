"""
DVWA 크롤러 - 동적 크롤링 버전 (Playwright 기반)
블랙박스 테스트를 위한 동적 웹 애플리케이션 크롤링
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlsplit
import json
from datetime import datetime
from playwright.sync_api import sync_playwright, Page, Browser, BrowserContext
import time

class DVWACrawler:
    def __init__(self, base_url, username="admin", password="password"):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.session = requests.Session()  # 세션 유지
        self.visited = set()
        self.found_urls = []
        self.found_forms = []
        self.found_endpoints = []  # GET 파라미터 포함한 엔드포인트

    def login(self):
        """DVWA 로그인"""
        print(f"[+] 로그인 시도: {self.username}")

        login_url = urljoin(self.base_url, "login.php")

        try:
            # 1. 로그인 페이지 방문 (CSRF 토큰 얻기)
            response = self.session.get(login_url)
            soup = BeautifulSoup(response.text, 'html.parser')

            # CSRF 토큰 찾기
            csrf_token = None
            csrf_input = soup.find('input', {'name': 'user_token'})
            if csrf_input:
                csrf_token = csrf_input.get('value')
                print(f"[+] CSRF 토큰 발견: {csrf_token[:20]}...")

            # 2. 로그인 폼 전송
            login_data = {
                'username': self.username,
                'password': self.password,
                'Login': 'Login'
            }

            if csrf_token:
                login_data['user_token'] = csrf_token

            response = self.session.post(login_url, data=login_data)

            # 로그인 성공 확인
            if 'login.php' not in response.url or 'Welcome' in response.text:
                print(f"[+] 로그인 성공! 현재 URL: {response.url}")
                return True
            else:
                print(f"[!] 로그인 실패")
                return False

        except Exception as e:
            print(f"[!] 로그인 에러: {e}")
            return False

    def crawl(self, url=None, max_depth=2, current_depth=0):
        """URL 크롤링 (세션 유지)"""

        if url is None:
            url = urljoin(self.base_url, "index.php")

        # 이미 방문했거나 깊이 제한 초과
        if url in self.visited or current_depth > max_depth:
            return

        print(f"[+] 크롤링 중: {url} (깊이: {current_depth})")
        self.visited.add(url)

        try:
            # 세션 사용하여 요청 (쿠키 자동 유지)
            response = self.session.get(url, timeout=5)
            response.raise_for_status() #이부분 나중에 뭐 결과저장할때 400에러 이런거 뜨면 따로 결과저장을 해서 다시 분석하면될듯.

            # 리다이렉트 체크
            if response.history:
                print(f"  → 리다이렉트: {url} -> {response.url}")

            # HTML 파싱
            soup = BeautifulSoup(response.text, 'html.parser')

            # 1. 링크 찾기
            self._find_links(soup, url)

            # 2. 폼 찾기 (퍼징 대상)
            self._find_forms(soup, url)

            # 재귀적으로 크롤링
            if current_depth < max_depth:
                for link in self.found_urls:
                    if self._is_same_domain(link) and link not in self.visited:
                        self.crawl(link, max_depth, current_depth + 1)

        except Exception as e:
            print(f"[!] 에러: {url} - {e}")

    def _find_links(self, soup, base_url):
        """모든 링크 추출 및 GET 파라미터 추출"""
        for link in soup.find_all('a', href=True):
            href = link['href']

            # 로그아웃, CAPTCHA 링크는 제외
            if 'logout' in href.lower() or 'captcha' in href.lower():
                continue

            full_url = urljoin(base_url, href)

            if full_url not in self.found_urls:
                self.found_urls.append(full_url)
                print(f"  → 링크: {full_url}")

                # GET 파라미터가 있으면 엔드포인트로 추출
                self._extract_get_params(full_url)

    def _extract_get_params(self, url):
        """URL에서 GET 파라미터 추출"""
        parsed = urlsplit(url)

        # 쿼리 파라미터가 없으면 리턴
        if not parsed.query:
            return

        # 외부 도메인은 제외
        if not self._is_same_domain(url):
            return

        # 파라미터 파싱
        params = parse_qs(parsed.query)

        # 베이스 URL (파라미터 제외)
        base_url_without_params = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # 이미 추가된 엔드포인트인지 확인
        endpoint_key = f"GET:{base_url_without_params}"
        existing_keys = [f"{e.get('method')}:{e.get('url')}" for e in self.found_endpoints]

        if endpoint_key in existing_keys:
            # 이미 있는 엔드포인트면 파라미터만 추가
            for endpoint in self.found_endpoints:
                if endpoint['method'] == 'GET' and endpoint['url'] == base_url_without_params:
                    existing_param_names = [p['name'] for p in endpoint['parameters']]
                    for param_name in params.keys():
                        if param_name not in existing_param_names:
                            endpoint['parameters'].append({
                                "name": param_name,
                                "type": "query",
                                "location": "query",
                                "default_value": params[param_name][0] if params[param_name] else "",
                                "required": True
                            })
            return

        # 새 엔드포인트 생성
        endpoint = {
            "url": base_url_without_params,
            "method": "GET",
            "page_url": url,
            "parameters": []
        }

        for param_name, param_values in params.items():
            param = {
                "name": param_name,
                "type": "query",
                "location": "query",
                "default_value": param_values[0] if param_values else "",
                "required": True
            }
            endpoint['parameters'].append(param)

        self.found_endpoints.append(endpoint)
        print(f"  → GET 엔드포인트: {base_url_without_params} (파라미터: {list(params.keys())})")

    def _find_forms(self, soup, base_url):
        """모든 폼 추출"""
        for form in soup.find_all('form'):
            form_data = {
                'url': base_url,
                'action': urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }

            # 입력 필드
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name'),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                }
                form_data['inputs'].append(input_data)

            self.found_forms.append(form_data)
            print(f"  → 폼: {form_data['method']} {form_data['action']}")
            print(f"     필드: {[inp['name'] for inp in form_data['inputs'] if inp['name']]}")

    def _is_same_domain(self, url):
        """같은 도메인 확인"""
        return urlparse(url).netloc == urlparse(self.base_url).netloc

    def export_to_json(self, filename="fuzzing_targets.json"):
        """퍼징 도구용 JSON 파일 생성"""

        data = {
            "target": self.base_url,
            "crawled_at": datetime.now().isoformat(),
            "statistics": {
                "pages_visited": len(self.visited),
                "urls_found": len(self.found_urls),
                "forms_found": len(self.found_forms),
                "get_endpoints_found": len(self.found_endpoints)
            },
            "endpoints": [],
            "session": {
                "cookies": {k: v for k, v in self.session.cookies.items()},
                "headers": dict(self.session.headers)
            }
        }

        # 1. GET 파라미터 엔드포인트 추가
        data['endpoints'].extend(self.found_endpoints)

        # 2. 폼을 엔드포인트로 변환
        for form in self.found_forms:
            endpoint = {
                "url": form['action'],
                "method": form['method'],
                "page_url": form['url'],
                "parameters": []
            }

            for inp in form['inputs']:
                if inp['name']:  # name이 있는 필드만
                    param = {
                        "name": inp['name'],
                        "type": inp['type'],
                        "location": "body" if form['method'] == "POST" else "query",
                        "default_value": inp['value'],
                        "required": inp['type'] not in ['hidden', 'submit']
                    }
                    endpoint['parameters'].append(param)

            data['endpoints'].append(endpoint)

        # JSON 저장
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"\n[+] JSON 저장 완료: {filename}")
        print(f"    - GET 엔드포인트: {len(self.found_endpoints)}개")
        print(f"    - 폼 엔드포인트: {len(self.found_forms)}개")
        print(f"    - 총 엔드포인트: {len(data['endpoints'])}개")
        return filename

    def show_results(self):
        """결과 출력"""
        print("\n" + "="*60)
        print(f"크롤링 완료!")
        print(f"방문한 페이지: {len(self.visited)}개")
        print(f"발견한 URL: {len(self.found_urls)}개")
        print(f"발견한 GET 엔드포인트: {len(self.found_endpoints)}개")
        print(f"발견한 폼: {len(self.found_forms)}개")
        print("="*60)

        # GET 엔드포인트 출력
        if self.found_endpoints:
            print("\n[GET 파라미터 엔드포인트]")
            for i, endpoint in enumerate(self.found_endpoints, 1):
                param_names = [p['name'] for p in endpoint['parameters']]
                print(f"{i}. {endpoint['url']}")
                print(f"   파라미터: {', '.join(param_names)}")

        # 폼 출력
        if self.found_forms:
            print("\n[폼 엔드포인트]")
            for i, form in enumerate(self.found_forms, 1):
                print(f"\n{i}. {form['method']} {form['action']}")
                print(f"   페이지: {form['url']}")
                for inp in form['inputs']:
                    if inp['name']:
                        print(f"   - {inp['name']} ({inp['type']})")


class PlaywrightBrowserController:
    """
    Playwright 브라우저 제어 기능

    3가지 주요 기능:
    1. 사용자 상호작용 모방 (User Interaction)
    2. 페이지 및 탐색 관리 (Page & Navigation Control)
    3. 상태 대기 및 분석 (State Waiting & Analysis)
    """

    def __init__(self, headless=False):
        self.headless = headless
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None

    def start_browser(self):
        """브라우저 시작"""
        print(f"[+] Playwright 브라우저 시작 (headless={self.headless})")

        self.playwright = sync_playwright().start()
        self.browser = self.playwright.chromium.launch(headless=self.headless)

        # 컨텍스트 생성 (쿠키/세션 유지)
        self.context = self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        )

        self.page = self.context.new_page()
        print(f"[+] 브라우저 준비 완료")

    # ========================================
    # 1. 사용자 상호작용 모방 (User Interaction)
    # ========================================

    def click_element(self, selector, timeout=5000):
        """
        특정 요소 클릭

        Args:
            selector: CSS 선택자 또는 XPath
            timeout: 대기 시간 (ms)
        """
        try:
            self.page.click(selector, timeout=timeout)
            print(f"[+] 클릭 완료: {selector}")
            return True
        except Exception as e:
            print(f"[!] 클릭 실패: {selector} - {e}")
            return False

    def fill_input(self, selector, text, timeout=5000):
        """
        텍스트 필드에 입력

        Args:
            selector: 입력 필드의 CSS 선택자
            text: 입력할 텍스트
            timeout: 대기 시간 (ms)
        """
        try:
            self.page.fill(selector, text, timeout=timeout)
            print(f"[+] 입력 완료: {selector} = '{text}'")
            return True
        except Exception as e:
            print(f"[!] 입력 실패: {selector} - {e}")
            return False

    def type_text(self, selector, text, delay=1000):
        """
        텍스트를 천천히 타이핑 (사람처럼)

        Args:
            selector: 입력 필드의 CSS 선택자
            text: 입력할 텍스트
            delay: 각 문자 사이 지연 시간 (ms)
        """
        try:
            self.page.type(selector, text, delay=delay)
            print(f"[+] 타이핑 완료: {selector} = '{text}'")
            return True
        except Exception as e:
            print(f"[!] 타이핑 실패: {selector} - {e}")
            return False

    def scroll_to_bottom(self):
        """페이지 맨 아래로 스크롤"""
        try:
            self.page.evaluate("window.scrollTo(0, document.body.scrollHeight);")
            print(f"[+] 페이지 하단으로 스크롤 완료")
            time.sleep(0.5)
            return True
        except Exception as e:
            print(f"[!] 스크롤 실패: {e}")
            return False

    def scroll_to_top(self):
        """페이지 맨 위로 스크롤"""
        try:
            self.page.evaluate("window.scrollTo(0, 0);")
            print(f"[+] 페이지 상단으로 스크롤 완료")
            time.sleep(0.5)
            return True
        except Exception as e:
            print(f"[!] 스크롤 실패: {e}")
            return False

    def scroll_to_element(self, selector):
        """특정 요소까지 스크롤"""
        try:
            self.page.locator(selector).scroll_into_view_if_needed()
            print(f"[+] 요소로 스크롤 완료: {selector}")
            return True
        except Exception as e:
            print(f"[!] 요소 스크롤 실패: {selector} - {e}")
            return False

    def hover_element(self, selector):
        """요소 위에 마우스 올리기 (호버)"""
        try:
            self.page.hover(selector)
            print(f"[+] 호버 완료: {selector}")
            return True
        except Exception as e:
            print(f"[!] 호버 실패: {selector} - {e}")
            return False

    def select_dropdown(self, selector, value=None, label=None, index=None):
        """
        드롭다운(select) 요소에서 옵션 선택

        Args:
            selector: select 요소의 CSS 선택자
            value: option의 value 속성으로 선택
            label: option의 텍스트로 선택
            index: 인덱스로 선택
        """
        try:
            if value:
                self.page.select_option(selector, value=value)
            elif label:
                self.page.select_option(selector, label=label)
            elif index is not None:
                self.page.select_option(selector, index=index)

            print(f"[+] 드롭다운 선택 완료: {selector}")
            return True
        except Exception as e:
            print(f"[!] 드롭다운 선택 실패: {selector} - {e}")
            return False

    # ========================================
    # 2. 페이지 및 탐색 관리 (Page & Navigation Control)
    # ========================================

    def navigate_to(self, url, wait_until='networkidle', timeout=30000):
        """
        URL로 이동

        Args:
            url: 이동할 URL
            wait_until: 대기 조건 ('load', 'domcontentloaded', 'networkidle')
            timeout: 타임아웃 (ms)
        """
        try:
            self.page.goto(url, wait_until=wait_until, timeout=timeout)
            print(f"[+] 페이지 이동 완료: {url}")
            return True
        except Exception as e:
            print(f"[!] 페이지 이동 실패: {url} - {e}")
            return False

    def go_back(self):
        """뒤로 가기"""
        try:
            self.page.go_back(wait_until='networkidle')
            print(f"[+] 뒤로 가기 완료")
            return True
        except Exception as e:
            print(f"[!] 뒤로 가기 실패: {e}")
            return False

    def go_forward(self):
        """앞으로 가기"""
        try:
            self.page.go_forward(wait_until='networkidle')
            print(f"[+] 앞으로 가기 완료")
            return True
        except Exception as e:
            print(f"[!] 앞으로 가기 실패: {e}")
            return False

    def reload_page(self):
        """페이지 새로고침"""
        try:
            self.page.reload(wait_until='networkidle')
            print(f"[+] 페이지 새로고침 완료")
            return True
        except Exception as e:
            print(f"[!] 페이지 새로고침 실패: {e}")
            return False

    def open_new_tab(self, url=None):
        """
        새 탭 열기

        Args:
            url: 새 탭에서 열 URL (선택)

        Returns:
            새 페이지 객체
        """
        try:
            new_page = self.context.new_page()
            if url:
                new_page.goto(url, wait_until='networkidle')
            print(f"[+] 새 탭 열기 완료")
            return new_page
        except Exception as e:
            print(f"[!] 새 탭 열기 실패: {e}")
            return None

    def switch_to_tab(self, page_index):
        """
        특정 탭으로 전환

        Args:
            page_index: 페이지 인덱스 (0부터 시작)
        """
        try:
            pages = self.context.pages
            if 0 <= page_index < len(pages):
                self.page = pages[page_index]
                print(f"[+] 탭 전환 완료: {page_index}")
                return True
            else:
                print(f"[!] 잘못된 탭 인덱스: {page_index}")
                return False
        except Exception as e:
            print(f"[!] 탭 전환 실패: {e}")
            return False

    def close_current_tab(self):
        """현재 탭 닫기"""
        try:
            self.page.close()
            # 남은 페이지 중 첫 번째로 전환
            pages = self.context.pages
            if pages:
                self.page = pages[0]
            print(f"[+] 탭 닫기 완료")
            return True
        except Exception as e:
            print(f"[!] 탭 닫기 실패: {e}")
            return False

    def get_current_url(self):
        """현재 페이지 URL 가져오기"""
        return self.page.url

    def get_page_title(self):
        """현재 페이지 제목 가져오기"""
        return self.page.title()

    # ========================================
    # 3. 상태 대기 및 분석 (State Waiting & Analysis)
    # ========================================

    def wait_for_selector(self, selector, state='visible', timeout=30000):
        """
        특정 요소가 나타날 때까지 대기

        Args:
            selector: CSS 선택자
            state: 대기할 상태 ('attached', 'detached', 'visible', 'hidden')
            timeout: 타임아웃 (ms)
        """
        try:
            self.page.wait_for_selector(selector, state=state, timeout=timeout)
            print(f"[+] 요소 대기 완료: {selector} (state={state})")
            return True
        except Exception as e:
            print(f"[!] 요소 대기 실패: {selector} - {e}")
            return False

    def wait_for_load_state(self, state='networkidle', timeout=30000):
        """
        페이지 로드 상태 대기

        Args:
            state: 대기할 상태 ('load', 'domcontentloaded', 'networkidle')
            timeout: 타임아웃 (ms)
        """
        try:
            self.page.wait_for_load_state(state, timeout=timeout)
            print(f"[+] 페이지 로드 대기 완료 (state={state})")
            return True
        except Exception as e:
            print(f"[!] 페이지 로드 대기 실패: {e}")
            return False

    def wait_for_url(self, url_pattern, timeout=30000):
        """
        URL이 특정 패턴과 일치할 때까지 대기

        Args:
            url_pattern: URL 패턴 (문자열 또는 정규표현식)
            timeout: 타임아웃 (ms)
        """
        try:
            self.page.wait_for_url(url_pattern, timeout=timeout)
            print(f"[+] URL 대기 완료: {url_pattern}")
            return True
        except Exception as e:
            print(f"[!] URL 대기 실패: {url_pattern} - {e}")
            return False

    def wait_for_request(self, url_pattern, timeout=30000):
        """
        특정 네트워크 요청이 시작될 때까지 대기

        Args:
            url_pattern: URL 패턴 (문자열 또는 정규표현식)
            timeout: 타임아웃 (ms)

        Returns:
            Request 객체
        """
        try:
            with self.page.expect_request(url_pattern, timeout=timeout) as request_info:
                request = request_info.value
            print(f"[+] 네트워크 요청 감지: {request.url}")
            return request
        except Exception as e:
            print(f"[!] 네트워크 요청 대기 실패: {url_pattern} - {e}")
            return None

    def wait_for_response(self, url_pattern, timeout=30000):
        """
        특정 네트워크 응답을 받을 때까지 대기

        Args:
            url_pattern: URL 패턴 (문자열 또는 정규표현식)
            timeout: 타임아웃 (ms)

        Returns:
            Response 객체
        """
        try:
            with self.page.expect_response(url_pattern, timeout=timeout) as response_info:
                response = response_info.value
            print(f"[+] 네트워크 응답 감지: {response.url} (status={response.status})")
            return response
        except Exception as e:
            print(f"[!] 네트워크 응답 대기 실패: {url_pattern} - {e}")
            return None

    def wait_for_timeout(self, milliseconds):
        """
        지정된 시간만큼 대기 (하드코딩된 sleep)

        Args:
            milliseconds: 대기 시간 (ms)
        """
        self.page.wait_for_timeout(milliseconds)
        print(f"[+] {milliseconds}ms 대기 완료")

    def wait_for_function(self, js_function, timeout=30000):
        """
        JavaScript 함수가 true를 반환할 때까지 대기

        Args:
            js_function: JavaScript 함수 (문자열)
            timeout: 타임아웃 (ms)
        """
        try:
            self.page.wait_for_function(js_function, timeout=timeout)
            print(f"[+] 함수 조건 대기 완료")
            return True
        except Exception as e:
            print(f"[!] 함수 조건 대기 실패: {e}")
            return False

    def get_element_text(self, selector):
        """요소의 텍스트 가져오기"""
        try:
            text = self.page.locator(selector).inner_text()
            return text
        except Exception as e:
            print(f"[!] 텍스트 가져오기 실패: {selector} - {e}")
            return None

    def get_element_attribute(self, selector, attribute):
        """요소의 속성 가져오기"""
        try:
            value = self.page.locator(selector).get_attribute(attribute)
            return value
        except Exception as e:
            print(f"[!] 속성 가져오기 실패: {selector}.{attribute} - {e}")
            return None

    def is_element_visible(self, selector):
        """요소가 보이는지 확인"""
        try:
            return self.page.locator(selector).is_visible()
        except:
            return False

    def is_element_enabled(self, selector):
        """요소가 활성화되어 있는지 확인"""
        try:
            return self.page.locator(selector).is_enabled()
        except:
            return False

    def get_page_html(self):
        """현재 페이지의 HTML 가져오기"""
        return self.page.content()

    def take_screenshot(self, filename="screenshot.png"):
        """스크린샷 저장"""
        try:
            self.page.screenshot(path=filename)
            print(f"[+] 스크린샷 저장: {filename}")
            return True
        except Exception as e:
            print(f"[!] 스크린샷 실패: {e}")
            return False

    def close(self):
        """브라우저 종료"""
        if self.page:
            self.page.close()
        if self.context:
            self.context.close()
        if self.browser:
            self.browser.close()
        if self.playwright:
            self.playwright.stop()
        print("[+] 브라우저 종료")


class NetworkTrafficCapturer:
    """
    네트워크 트래픽 캡처 기능

    주요 기능:
    1. HTTP 요청/응답 인터셉션
    2. API 엔드포인트 자동 추출
    3. AJAX/Fetch 요청 감지 및 기록
    """

    def __init__(self, page):
        """
        Args:
            page: Playwright Page 객체
        """
        self.page = page
        self.captured_requests = []   # 모든 HTTP 요청 저장
        self.captured_responses = []  # 모든 HTTP 응답 저장
        self.endpoints = []           # 추출된 API 엔드포인트
        self.ajax_requests = []       # AJAX/Fetch 요청만 따로 저장

        # 리스너 등록
        self._setup_listeners()

    def _setup_listeners(self):
        """네트워크 요청/응답 리스너 등록"""
        self.page.on('request', self._on_request)
        self.page.on('response', self._on_response)
        print("[+] 네트워크 트래픽 캡처 시작")

    # ========================================
    # 1. HTTP 요청/응답 인터셉션
    # ========================================

    def _on_request(self, request):
        """
        모든 HTTP 요청 캡처

        Args:
            request: Playwright Request 객체
        """
        # 리소스 타입 확인 (이미지, CSS, 폰트 제외 가능)
        resource_type = request.resource_type

        # 필터링: 불필요한 리소스 제외 (선택적)
        if resource_type in ['image', 'stylesheet', 'font', 'media']:
            return

        # 요청 데이터 수집
        req_data = {
            'url': request.url,
            'method': request.method,
            'resource_type': resource_type,
            'headers': dict(request.headers),
            'post_data': request.post_data,
            'timestamp': datetime.now().isoformat()
        }

        self.captured_requests.append(req_data)

        # AJAX/Fetch 요청 감지
        if resource_type in ['xhr', 'fetch']:
            self._on_ajax_request(request, req_data)
            print(f"  → [AJAX] {request.method} {request.url}")
        else:
            print(f"  → [HTTP] {request.method} {request.url}")

    def _on_response(self, response):
        """
        모든 HTTP 응답 캡처

        Args:
            response: Playwright Response 객체
        """
        request = response.request
        resource_type = request.resource_type

        # 필터링: 불필요한 리소스 제외
        if resource_type in ['image', 'stylesheet', 'font', 'media']:
            return

        # 응답 데이터 수집
        resp_data = {
            'url': response.url,
            'status': response.status,
            'status_text': response.status_text,
            'method': request.method,
            'resource_type': resource_type,
            'headers': dict(response.headers),
            'timestamp': datetime.now().isoformat()
        }

        # 응답 본문 수집 (JSON만 수집)
        content_type = response.headers.get('content-type', '')
        if 'application/json' in content_type:
            try:
                resp_data['body'] = response.json()
            except:
                resp_data['body'] = None

        self.captured_responses.append(resp_data)

        # API 엔드포인트 자동 추출
        if resource_type in ['xhr', 'fetch', 'document']:
            self._extract_endpoint(request, response)

        print(f"  ← [응답] {response.status} {response.url}")

    # ========================================
    # 2. API 엔드포인트 자동 추출
    # ========================================

    def _extract_endpoint(self, request, response):
        """
        네트워크 요청에서 API 엔드포인트 추출

        Args:
            request: Playwright Request 객체
            response: Playwright Response 객체
        """
        url = request.url
        method = request.method

        # URL 파싱
        parsed = urlsplit(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # 중복 확인
        endpoint_key = f"{method}:{base_url}"
        existing_keys = [f"{e['method']}:{e['url']}" for e in self.endpoints]

        if endpoint_key in existing_keys:
            return

        # 엔드포인트 데이터 생성
        endpoint = {
            'url': base_url,
            'method': method,
            'parameters': [],
            'source': 'network_capture',
            'status': response.status,
            'content_type': response.headers.get('content-type', '')
        }

        # GET 파라미터 추출
        if parsed.query:
            params = parse_qs(parsed.query)
            for param_name, param_values in params.items():
                endpoint['parameters'].append({
                    'name': param_name,
                    'type': 'query',
                    'location': 'query',
                    'example_value': param_values[0] if param_values else '',
                    'required': True
                })

        # POST 데이터 추출
        if method in ['POST', 'PUT', 'PATCH'] and request.post_data:
            self._extract_post_parameters(request, endpoint)

        self.endpoints.append(endpoint)
        print(f"  → [엔드포인트 추출] {method} {base_url} (파라미터: {len(endpoint['parameters'])}개)")

    def _extract_post_parameters(self, request, endpoint):
        """
        POST 요청에서 파라미터 추출

        Args:
            request: Playwright Request 객체
            endpoint: 엔드포인트 딕셔너리
        """
        post_data = request.post_data
        content_type = request.headers.get('content-type', '')

        try:
            # JSON 데이터
            if 'application/json' in content_type:
                post_json = json.loads(post_data)
                for key, value in post_json.items():
                    endpoint['parameters'].append({
                        'name': key,
                        'type': 'json',
                        'location': 'body',
                        'example_value': value,
                        'required': True
                    })

            # Form 데이터
            elif 'application/x-www-form-urlencoded' in content_type:
                params = parse_qs(post_data)
                for param_name, param_values in params.items():
                    endpoint['parameters'].append({
                        'name': param_name,
                        'type': 'form',
                        'location': 'body',
                        'example_value': param_values[0] if param_values else '',
                        'required': True
                    })

            # Multipart Form 데이터
            elif 'multipart/form-data' in content_type:
                endpoint['parameters'].append({
                    'name': 'file_upload',
                    'type': 'multipart',
                    'location': 'body',
                    'example_value': 'binary_data',
                    'required': True
                })
        except Exception as e:
            print(f"  [!] POST 파라미터 추출 실패: {e}")

    # ========================================
    # 3. AJAX/Fetch 요청 감지 및 기록
    # ========================================

    def _on_ajax_request(self, request, req_data):
        """
        AJAX/Fetch 요청 특별 처리

        Args:
            request: Playwright Request 객체
            req_data: 요청 데이터 딕셔너리
        """
        ajax_data = {
            'url': request.url,
            'method': request.method,
            'type': request.resource_type,  # 'xhr' 또는 'fetch'
            'headers': dict(request.headers),
            'post_data': request.post_data,
            'timestamp': req_data['timestamp']
        }

        # AJAX 특성 분석
        ajax_data['is_api_call'] = self._is_likely_api_call(request.url)
        ajax_data['accepts_json'] = 'application/json' in request.headers.get('accept', '')

        self.ajax_requests.append(ajax_data)

    def _is_likely_api_call(self, url):
        """
        URL이 API 호출인지 추측

        Args:
            url: 요청 URL

        Returns:
            bool: API 호출 가능성
        """
        api_indicators = ['/api/', '/rest/', '/graphql', '/v1/', '/v2/', '.json', '/ajax/']
        return any(indicator in url.lower() for indicator in api_indicators)

    # ========================================
    # 유틸리티 메서드
    # ========================================

    def get_all_requests(self):
        """모든 캡처된 요청 반환"""
        return self.captured_requests

    def get_all_responses(self):
        """모든 캡처된 응답 반환"""
        return self.captured_responses

    def get_endpoints(self):
        """추출된 엔드포인트 반환"""
        return self.endpoints

    def get_ajax_requests(self):
        """AJAX/Fetch 요청만 반환"""
        return self.ajax_requests

    def get_statistics(self):
        """통계 정보 반환"""
        return {
            'total_requests': len(self.captured_requests),
            'total_responses': len(self.captured_responses),
            'endpoints_found': len(self.endpoints),
            'ajax_requests': len(self.ajax_requests),
            'http_methods': self._count_methods()
        }

    def _count_methods(self):
        """HTTP 메서드별 개수 집계"""
        methods = {}
        for req in self.captured_requests:
            method = req['method']
            methods[method] = methods.get(method, 0) + 1
        return methods

    def clear_data(self):
        """수집된 데이터 초기화"""
        self.captured_requests.clear()
        self.captured_responses.clear()
        self.endpoints.clear()
        self.ajax_requests.clear()
        print("[+] 네트워크 데이터 초기화 완료")

    def export_to_json(self, filename="network_traffic.json"):
        """수집된 네트워크 데이터를 JSON으로 저장"""
        data = {
            'captured_at': datetime.now().isoformat(),
            'statistics': self.get_statistics(),
            'endpoints': self.endpoints,
            'ajax_requests': self.ajax_requests,
            'all_requests': self.captured_requests,
            'all_responses': self.captured_responses
        }

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"[+] 네트워크 트래픽 저장: {filename}")
        print(f"    - 총 요청: {len(self.captured_requests)}개")
        print(f"    - 엔드포인트: {len(self.endpoints)}개")
        print(f"    - AJAX 요청: {len(self.ajax_requests)}개")

    def show_summary(self):
        """캡처된 데이터 요약 출력"""
        stats = self.get_statistics()

        print("\n" + "="*60)
        print("네트워크 트래픽 캡처 요약")
        print("="*60)
        print(f"총 요청 수: {stats['total_requests']}개")
        print(f"총 응답 수: {stats['total_responses']}개")
        print(f"발견된 엔드포인트: {stats['endpoints_found']}개")
        print(f"AJAX 요청: {stats['ajax_requests']}개")

        print("\nHTTP 메서드 분포:")
        for method, count in stats['http_methods'].items():
            print(f"  {method}: {count}개")

        if self.endpoints:
            print("\n발견된 엔드포인트:")
            for i, endpoint in enumerate(self.endpoints[:10], 1):  # 최대 10개만
                params_info = f" ({len(endpoint['parameters'])}개 파라미터)" if endpoint['parameters'] else ""
                print(f"  {i}. {endpoint['method']} {endpoint['url']}{params_info}")

            if len(self.endpoints) > 10:
                print(f"  ... 외 {len(self.endpoints) - 10}개")

        print("="*60)


class DynamicContentAnalyzer:
    """
    동적 콘텐츠 분석 기능 (3단계)

    주요 기능:
    1. JavaScript 실행 후 DOM 분석
    2. 동적으로 생성된 링크/폼 추출
    3. Lazy Loading 콘텐츠 로드 (무한 스크롤, 더보기 버튼)
    """

    def __init__(self, page, base_url):
        """
        Args:
            page: Playwright Page 객체
            base_url: 기준 URL (도메인 필터링용)
        """
        self.page = page
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc

        # 수집된 데이터
        self.dynamic_links = []
        self.dynamic_forms = []
        self.interactive_elements = []
        self.spa_routes = []
        self.interaction_results = {}  # 인터랙티브 요소 클릭 결과 저장

    # ========================================
    # 1. JavaScript 실행 후 DOM 분석
    # ========================================

    def analyze_rendered_dom(self):
        """
        JavaScript 실행 후 최종 렌더링된 DOM을 분석

        Returns:
            dict: 분석 결과
        """
        print("[+] DOM 분석 시작 (JavaScript 실행 후)")

        # 페이지가 완전히 로드될 때까지 대기
        self.page.wait_for_load_state('networkidle', timeout=10000)

        # DOM 통계 수집
        dom_stats = self.page.evaluate("""
            () => {
                return {
                    total_elements: document.querySelectorAll('*').length,
                    links: document.querySelectorAll('a[href]').length,
                    forms: document.querySelectorAll('form').length,
                    buttons: document.querySelectorAll('button').length,
                    inputs: document.querySelectorAll('input').length,
                    iframes: document.querySelectorAll('iframe').length,
                    scripts: document.querySelectorAll('script').length
                };
            }
        """)

        print(f"  → 총 요소: {dom_stats['total_elements']}개")
        print(f"  → 링크: {dom_stats['links']}개")
        print(f"  → 폼: {dom_stats['forms']}개")
        print(f"  → 버튼: {dom_stats['buttons']}개")
        print(f"  → 입력 필드: {dom_stats['inputs']}개")

        return dom_stats

    def get_rendered_html(self):
        """JavaScript 실행 후 최종 HTML 가져오기"""
        return self.page.content()

    # ========================================
    # 2. 동적으로 생성된 링크/폼 추출
    # ========================================

    def extract_dynamic_links(self):
        """
        JavaScript로 동적 생성된 링크 추출

        Returns:
            list: 링크 정보 리스트
        """
        print("[+] 동적 링크 추출 중...")

        links = self.page.evaluate("""
            () => {
                const links = [];
                document.querySelectorAll('a[href]').forEach(link => {
                    links.push({
                        href: link.href,
                        text: link.innerText.trim(),
                        id: link.id || null,
                        class: link.className || null,
                        target: link.target || null,
                        rel: link.rel || null
                    });
                });
                return links;
            }
        """)

        # 같은 도메인 필터링 및 중복 제거
        filtered_links = []
        seen_urls = set()

        for link in links:
            href = link['href']

            # 같은 도메인만
            if not self._is_same_domain(href):
                continue

            # 중복 제거
            if href in seen_urls:
                continue

            # 로그아웃, CAPTCHA 링크 제외
            if 'logout' in href.lower() or 'captcha' in href.lower():
                continue

            seen_urls.add(href)
            filtered_links.append(link)

        self.dynamic_links = filtered_links
        print(f"  → 발견된 동적 링크: {len(filtered_links)}개")

        return filtered_links

    def extract_dynamic_forms(self):
        """
        JavaScript로 동적 생성된 폼 추출

        Returns:
            list: 폼 정보 리스트
        """
        print("[+] 동적 폼 추출 중...")

        forms = self.page.evaluate("""
            () => {
                const forms = [];
                document.querySelectorAll('form').forEach((form, index) => {
                    const inputs = [];

                    // 모든 입력 필드 수집
                    form.querySelectorAll('input, textarea, select').forEach(input => {
                        inputs.push({
                            name: input.name || null,
                            type: input.type || 'text',
                            id: input.id || null,
                            value: input.value || '',
                            placeholder: input.placeholder || null,
                            required: input.required || false
                        });
                    });

                    forms.push({
                        index: index,
                        action: form.action || window.location.href,
                        method: form.method || 'get',
                        id: form.id || null,
                        class: form.className || null,
                        inputs: inputs
                    });
                });
                return forms;
            }
        """)

        self.dynamic_forms = forms
        print(f"  → 발견된 동적 폼: {len(forms)}개")

        for i, form in enumerate(forms, 1):
            input_names = [inp['name'] for inp in form['inputs'] if inp['name']]
            print(f"    {i}. {form['method'].upper()} {form['action']}")
            print(f"       필드: {input_names}")

        return forms

    def extract_all_interactive_elements(self):
        """
        모든 인터랙티브 요소 추출 (버튼, 클릭 가능한 요소 등)

        Returns:
            list: 인터랙티브 요소 리스트
        """
        print("[+] 인터랙티브 요소 추출 중...")

        elements = self.page.evaluate("""
            () => {
                const elements = [];

                // 버튼
                document.querySelectorAll('button').forEach(btn => {
                    elements.push({
                        type: 'button',
                        text: btn.innerText.trim(),
                        id: btn.id || null,
                        class: btn.className || null,
                        onclick: btn.onclick ? true : false
                    });
                });

                // 클릭 이벤트가 있는 요소
                document.querySelectorAll('[onclick]').forEach(el => {
                    if (el.tagName !== 'BUTTON' && el.tagName !== 'A') {
                        elements.push({
                            type: 'clickable_element',
                            tag: el.tagName.toLowerCase(),
                            text: el.innerText.trim().substring(0, 50),
                            id: el.id || null,
                            class: el.className || null,
                            onclick: true
                        });
                    }
                });

                return elements;
            }
        """)

        self.interactive_elements = elements
        print(f"  → 발견된 인터랙티브 요소: {len(elements)}개")

        return elements

    # ========================================
    # 3. Lazy Loading 콘텐츠 로드
    # ========================================

    def handle_infinite_scroll(self, max_scrolls=10, scroll_pause_time=1000):
        """
        무한 스크롤 페이지 처리

        Args:
            max_scrolls: 최대 스크롤 횟수
            scroll_pause_time: 스크롤 후 대기 시간 (ms)

        Returns:
            int: 로드된 새 콘텐츠 개수
        """
        print(f"[+] 무한 스크롤 처리 중 (최대 {max_scrolls}회)...")

        initial_height = self.page.evaluate("document.body.scrollHeight")
        scroll_count = 0
        new_content_loaded = 0

        for i in range(max_scrolls):
            # 현재 높이 저장
            current_height = self.page.evaluate("document.body.scrollHeight")

            # 맨 아래로 스크롤
            self.page.evaluate("window.scrollTo(0, document.body.scrollHeight);")
            print(f"  → 스크롤 {i+1}/{max_scrolls}...")

            # 대기
            self.page.wait_for_timeout(scroll_pause_time)

            # 새 높이 확인
            new_height = self.page.evaluate("document.body.scrollHeight")

            # 더 이상 로드되지 않으면 중단
            if new_height == current_height:
                print(f"  → 더 이상 콘텐츠가 로드되지 않습니다.")
                break

            scroll_count += 1
            new_content_loaded += (new_height - current_height)

        print(f"  → 총 {scroll_count}회 스크롤, {new_content_loaded}px 콘텐츠 로드됨")
        return scroll_count

    def handle_load_more_button(self, button_selectors=None, max_clicks=10):
        """
        "더보기" 버튼 자동 클릭

        Args:
            button_selectors: 버튼 선택자 리스트 (None이면 자동 탐지)
            max_clicks: 최대 클릭 횟수

        Returns:
            int: 클릭 횟수
        """
        print("[+] '더보기' 버튼 처리 중...")

        # 기본 선택자
        if button_selectors is None:
            button_selectors = [
                'button:has-text("더보기")',
                'button:has-text("Load More")',
                'button:has-text("Show More")',
                'a:has-text("더보기")',
                'a:has-text("Load More")',
                '.load-more',
                '#load-more',
                '[data-load-more]'
            ]

        click_count = 0

        for i in range(max_clicks):
            button_found = False

            # 모든 선택자 시도
            for selector in button_selectors:
                try:
                    # 버튼이 보이는지 확인
                    if self.page.locator(selector).is_visible(timeout=1000):
                        # 클릭
                        self.page.click(selector)
                        print(f"  → '더보기' 버튼 클릭 {i+1}/{max_clicks}")
                        click_count += 1
                        button_found = True

                        # 로딩 대기
                        self.page.wait_for_load_state('networkidle', timeout=5000)
                        break
                except:
                    continue

            # 버튼을 찾지 못하면 중단
            if not button_found:
                print(f"  → 더 이상 '더보기' 버튼을 찾을 수 없습니다.")
                break

        print(f"  → 총 {click_count}회 클릭 완료")
        return click_count

    def detect_lazy_loaded_images(self):
        """
        지연 로딩된 이미지 감지 및 로드

        Returns:
            int: 로드된 이미지 개수
        """
        print("[+] 지연 로딩 이미지 처리 중...")

        # data-src 속성을 가진 이미지 찾기
        lazy_images = self.page.evaluate("""
            () => {
                const images = document.querySelectorAll('img[data-src], img[loading="lazy"]');
                return images.length;
            }
        """)

        if lazy_images > 0:
            print(f"  → 발견된 지연 로딩 이미지: {lazy_images}개")

            # 페이지 끝까지 스크롤하여 모든 이미지 로드
            self.handle_infinite_scroll(max_scrolls=5, scroll_pause_time=500)

        return lazy_images

    # ========================================
    # 4. 인터랙티브 요소 자동 트리거
    # ========================================

    def trigger_interactive_elements(self, max_clicks=10):
        """
        발견한 모든 인터랙티브 요소를 자동으로 클릭하여 숨겨진 AJAX 요청 발견

        Args:
            max_clicks: 최대 클릭할 요소 개수

        Returns:
            dict: 클릭 결과 및 발견된 네트워크 요청 정보
        """
        print(f"[+] 인터랙티브 요소 자동 트리거 시작 (최대 {max_clicks}개)...")

        # 위험한 키워드 (클릭하면 안 되는 것들)
        dangerous_keywords = [
            'logout', 'delete', 'remove', 'reset', 'clear',
            'destroy', 'drop', 'terminate', 'cancel', 'exit'
        ]

        results = {
            'clicked_elements': [],
            'skipped_elements': [],
            'errors': []
        }

        # 현재 URL 저장 (복원용)
        original_url = self.page.url

        # 1. 버튼 클릭
        buttons = self.page.locator('button').all()
        print(f"  → 발견된 버튼: {len(buttons)}개")

        click_count = 0
        for i, button in enumerate(buttons):
            if click_count >= max_clicks:
                break

            try:
                # 버튼 텍스트 가져오기
                button_text = button.inner_text().strip().lower()
                button_id = button.get_attribute('id') or ''
                button_class = button.get_attribute('class') or ''

                # 위험한 버튼 필터링
                if any(keyword in button_text or keyword in button_id.lower() or keyword in button_class.lower()
                       for keyword in dangerous_keywords):
                    print(f"    ⚠️  스킵 (위험): '{button_text}'")
                    results['skipped_elements'].append({
                        'type': 'button',
                        'text': button_text,
                        'reason': 'dangerous_keyword'
                    })
                    continue

                # 버튼이 보이고 활성화되어 있는지 확인
                if not button.is_visible() or not button.is_enabled():
                    continue

                print(f"    🖱️  클릭: '{button_text}' (#{i+1})")

                # 클릭 전 네트워크 요청 수 기록
                # (NetworkCapturer가 자동으로 캡처할 것임)

                # 버튼 클릭
                button.click(timeout=3000)
                click_count += 1

                # 클릭 후 짧은 대기 (AJAX 요청 완료까지)
                self.page.wait_for_timeout(1000)

                # 클릭 결과 기록
                results['clicked_elements'].append({
                    'type': 'button',
                    'text': button_text,
                    'id': button_id,
                    'index': i
                })

                # URL이 변경되었다면 원래 페이지로 복원
                if self.page.url != original_url:
                    print(f"    ↩️  페이지 변경 감지, 복원 중...")
                    self.page.goto(original_url, wait_until='networkidle')

            except Exception as e:
                error_msg = f"버튼 클릭 실패 #{i}: {str(e)[:50]}"
                print(f"    ❌ {error_msg}")
                results['errors'].append(error_msg)
                # 에러 발생 시 원래 페이지로 복원 시도
                try:
                    if self.page.url != original_url:
                        self.page.goto(original_url, wait_until='networkidle')
                except:
                    pass

        # 2. 드롭다운(select) 변경
        selects = self.page.locator('select').all()
        print(f"  → 발견된 드롭다운: {len(selects)}개")

        for i, select in enumerate(selects):
            if click_count >= max_clicks:
                break

            try:
                # 모든 옵션 가져오기
                options = select.locator('option').all()

                if len(options) <= 1:
                    continue

                select_name = select.get_attribute('name') or f'select_{i}'

                # 첫 번째 옵션 제외하고 하나만 선택해보기
                if len(options) > 1:
                    option_value = options[1].get_attribute('value')
                    option_text = options[1].inner_text().strip()

                    print(f"    🖱️  드롭다운 변경: '{select_name}' → '{option_text}'")

                    select.select_option(value=option_value)
                    click_count += 1

                    # 변경 후 대기
                    self.page.wait_for_timeout(1000)

                    results['clicked_elements'].append({
                        'type': 'select',
                        'name': select_name,
                        'value': option_value,
                        'text': option_text
                    })

                    # URL 변경 체크 및 복원
                    if self.page.url != original_url:
                        self.page.goto(original_url, wait_until='networkidle')

            except Exception as e:
                error_msg = f"드롭다운 변경 실패 #{i}: {str(e)[:50]}"
                print(f"    ❌ {error_msg}")
                results['errors'].append(error_msg)

        # 3. JavaScript 링크 클릭 (SPA, 동적 동작만)
        js_links = self.page.evaluate("""
            () => {
                const links = [];
                document.querySelectorAll('a[href]').forEach((link, index) => {
                    const href = link.getAttribute('href');
                    const onclick = link.getAttribute('onclick');

                    // 선택적 클릭: href가 의미 없고 onclick이 있는 경우만
                    // (SPA, 동적 AJAX 호출 등)
                    if (onclick && (href === '#' || href.startsWith('javascript:') || href === '')) {
                        links.push({
                            index: index,
                            text: link.innerText.trim(),
                            href: href,
                            id: link.id || null,
                            hasOnclick: true
                        });
                    }
                });
                return links;
            }
        """)

        print(f"  → 발견된 JavaScript 링크: {len(js_links)}개")

        for link_info in js_links:
            if click_count >= max_clicks:
                break

            try:
                link_text = link_info['text'].lower()
                link_id = (link_info['id'] or '').lower()

                # 위험한 링크 필터링
                if any(keyword in link_text or keyword in link_id
                       for keyword in dangerous_keywords):
                    print(f"    ⚠️  스킵 (위험): '{link_info['text']}'")
                    results['skipped_elements'].append({
                        'type': 'js_link',
                        'text': link_info['text'],
                        'reason': 'dangerous_keyword'
                    })
                    continue

                print(f"    🖱️  JS 링크 클릭: '{link_info['text']}' (href={link_info['href']})")

                # 인덱스로 링크 찾아서 클릭
                links = self.page.locator('a[href]').all()
                if link_info['index'] < len(links):
                    links[link_info['index']].click(timeout=3000)
                    click_count += 1

                    # 클릭 후 대기
                    self.page.wait_for_timeout(1000)

                    results['clicked_elements'].append({
                        'type': 'js_link',
                        'text': link_info['text'],
                        'href': link_info['href'],
                        'has_onclick': link_info['hasOnclick']
                    })

                    # URL 변경 체크 및 복원
                    if self.page.url != original_url:
                        print(f"    ↩️  페이지 변경 감지, 복원 중...")
                        self.page.goto(original_url, wait_until='networkidle')

            except Exception as e:
                error_msg = f"JS 링크 클릭 실패: {str(e)[:50]}"
                print(f"    ❌ {error_msg}")
                results['errors'].append(error_msg)
                # 에러 발생 시 복원
                try:
                    if self.page.url != original_url:
                        self.page.goto(original_url, wait_until='networkidle')
                except:
                    pass

        # 4. 폼 제출 (테스트 데이터)
        forms = self.page.locator('form').all()
        print(f"  → 발견된 폼: {len(forms)}개")

        for i, form in enumerate(forms):
            if click_count >= max_clicks:
                break

            try:
                form_action = form.get_attribute('action') or 'current_page'
                form_method = (form.get_attribute('method') or 'GET').upper()

                # 폼 내부의 모든 input 찾기
                inputs = form.locator('input, textarea').all()
                submit_button = None

                # submit 버튼 찾기
                try:
                    submit_button = form.locator('button[type="submit"], input[type="submit"]').first
                except:
                    pass

                if not submit_button:
                    continue

                print(f"    📝 폼 제출 시도: {form_method} {form_action}")

                # 각 입력 필드에 테스트 데이터 입력
                filled_fields = []
                for inp in inputs:
                    try:
                        input_type = inp.get_attribute('type') or 'text'
                        input_name = inp.get_attribute('name') or ''

                        # hidden, submit, button은 스킵
                        if input_type in ['hidden', 'submit', 'button', 'file']:
                            continue

                        # 위험한 필드명 스킵 (delete, remove 등)
                        if any(keyword in input_name.lower() for keyword in dangerous_keywords):
                            print(f"      ⚠️  위험한 필드 스킵: {input_name}")
                            continue

                        # 타입별 테스트 데이터 입력
                        test_value = self._generate_test_data(input_type, input_name)

                        if test_value and inp.is_visible() and inp.is_enabled():
                            if input_type == 'checkbox':
                                if not inp.is_checked():
                                    inp.check()
                                    filled_fields.append(f"{input_name}=checked")
                            elif input_type == 'radio':
                                inp.check()
                                filled_fields.append(f"{input_name}={test_value}")
                            else:
                                inp.fill(test_value)
                                filled_fields.append(f"{input_name}={test_value}")

                    except Exception as e:
                        continue

                if not filled_fields:
                    print(f"      ⚠️  입력 가능한 필드 없음, 스킵")
                    continue

                print(f"      입력 완료: {', '.join(filled_fields[:3])}...")

                # submit 버튼 클릭
                submit_button.click(timeout=3000)
                click_count += 1

                # 제출 후 대기
                self.page.wait_for_timeout(1500)

                results['clicked_elements'].append({
                    'type': 'form',
                    'action': form_action,
                    'method': form_method,
                    'filled_fields': filled_fields
                })

                print(f"      ✅ 폼 제출 완료")

                # URL 변경 체크 및 복원
                if self.page.url != original_url:
                    print(f"    ↩️  페이지 변경 감지, 복원 중...")
                    self.page.goto(original_url, wait_until='networkidle')

            except Exception as e:
                error_msg = f"폼 제출 실패 #{i}: {str(e)[:50]}"
                print(f"    ❌ {error_msg}")
                results['errors'].append(error_msg)
                # 에러 발생 시 복원
                try:
                    if self.page.url != original_url:
                        self.page.goto(original_url, wait_until='networkidle')
                except:
                    pass

        print(f"  ✅ 총 {click_count}개 요소 트리거 완료")
        print(f"  ⚠️  {len(results['skipped_elements'])}개 스킵")
        print(f"  ❌ {len(results['errors'])}개 에러")

        # 결과 저장
        self.interaction_results = results

        return results

    def _generate_test_data(self, input_type, input_name):
        """
        입력 필드 타입과 이름에 따라 안전한 테스트 데이터 생성

        Args:
            input_type: input 타입 (text, email, password 등)
            input_name: input name 속성

        Returns:
            str: 테스트 데이터
        """
        name_lower = input_name.lower()

        # 이름 기반 매칭
        if 'email' in name_lower or 'mail' in name_lower:
            return 'test@example.com'
        elif 'user' in name_lower or 'login' in name_lower:
            return 'testuser'
        elif 'pass' in name_lower or 'pwd' in name_lower:
            return 'Test123!'
        elif 'phone' in name_lower or 'tel' in name_lower:
            return '010-1234-5678'
        elif 'age' in name_lower:
            return '25'
        elif 'url' in name_lower or 'website' in name_lower:
            return 'http://example.com'
        elif 'date' in name_lower:
            return '2024-01-01'

        # 타입 기반 매칭
        if input_type == 'email':
            return 'test@example.com'
        elif input_type == 'password':
            return 'Test123!'
        elif input_type == 'number':
            return '123'
        elif input_type == 'tel':
            return '010-1234-5678'
        elif input_type == 'url':
            return 'http://example.com'
        elif input_type == 'date':
            return '2024-01-01'
        elif input_type == 'time':
            return '12:00'
        elif input_type == 'text' or input_type == 'search':
            return 'test'
        elif input_type == 'textarea':
            return 'test message'
        else:
            return 'test'

    # ========================================
    # 5. SPA (Single Page Application) 라우트 감지
    # ========================================

    def detect_spa_routes(self):
        """
        SPA 라우트 감지 (Hash 라우팅, History API)

        Returns:
            list: 발견된 라우트 리스트
        """
        print("[+] SPA 라우트 감지 중...")

        routes = self.page.evaluate("""
            () => {
                const routes = new Set();

                // Hash 기반 라우트 (#/page)
                document.querySelectorAll('a[href*="#"]').forEach(link => {
                    const hash = link.hash;
                    if (hash && hash.length > 1) {
                        routes.add(hash);
                    }
                });

                // data-route 속성
                document.querySelectorAll('[data-route]').forEach(el => {
                    routes.add(el.dataset.route);
                });

                return Array.from(routes);
            }
        """)

        self.spa_routes = routes
        print(f"  → 발견된 SPA 라우트: {len(routes)}개")

        if routes:
            for route in routes[:10]:  # 최대 10개만 출력
                print(f"    - {route}")

        return routes

    # ========================================
    # 유틸리티 메서드
    # ========================================

    def _is_same_domain(self, url):
        """같은 도메인인지 확인"""
        try:
            return urlparse(url).netloc == self.base_domain
        except:
            return False

    def get_all_data(self):
        """수집된 모든 데이터 반환"""
        return {
            'dynamic_links': self.dynamic_links,
            'dynamic_forms': self.dynamic_forms,
            'interactive_elements': self.interactive_elements,
            'spa_routes': self.spa_routes,
            'interaction_results': self.interaction_results
        }

    def export_to_json(self, filename="dynamic_content.json"):
        """수집된 데이터를 JSON으로 저장"""
        data = {
            'analyzed_at': datetime.now().isoformat(),
            'base_url': self.base_url,
            'statistics': {
                'dynamic_links': len(self.dynamic_links),
                'dynamic_forms': len(self.dynamic_forms),
                'interactive_elements': len(self.interactive_elements),
                'spa_routes': len(self.spa_routes)
            },
            'dynamic_links': self.dynamic_links,
            'dynamic_forms': self.dynamic_forms,
            'interactive_elements': self.interactive_elements,
            'spa_routes': self.spa_routes
        }

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"\n[+] 동적 콘텐츠 분석 결과 저장: {filename}")
        print(f"    - 동적 링크: {len(self.dynamic_links)}개")
        print(f"    - 동적 폼: {len(self.dynamic_forms)}개")
        print(f"    - 인터랙티브 요소: {len(self.interactive_elements)}개")
        print(f"    - SPA 라우트: {len(self.spa_routes)}개")

    def show_summary(self):
        """분석 결과 요약 출력"""
        print("\n" + "="*60)
        print("동적 콘텐츠 분석 요약")
        print("="*60)
        print(f"동적 링크: {len(self.dynamic_links)}개")
        print(f"동적 폼: {len(self.dynamic_forms)}개")
        print(f"인터랙티브 요소: {len(self.interactive_elements)}개")
        print(f"SPA 라우트: {len(self.spa_routes)}개")

        if self.dynamic_forms:
            print("\n발견된 동적 폼:")
            for i, form in enumerate(self.dynamic_forms[:5], 1):
                print(f"  {i}. {form['method'].upper()} {form['action']}")
                input_names = [inp['name'] for inp in form['inputs'] if inp['name']]
                print(f"     필드: {input_names}")

            if len(self.dynamic_forms) > 5:
                print(f"  ... 외 {len(self.dynamic_forms) - 5}개")

        print("="*60)


class AutomatedDynamicCrawler:
    """
    동적 크롤링 통합 및 자동화 (4단계)

    주요 기능:
    1. Playwright 로그인 자동화
    2. 재귀적 동적 크롤링 (1~3단계 통합)
    3. 수집 데이터 통합 JSON 저장
    """

    def __init__(self, base_url, username=None, password=None, headless=False):
        """
        Args:
            base_url: 크롤링 대상 URL
            username: 로그인 사용자명 (선택)
            password: 로그인 비밀번호 (선택)
            headless: 헤드리스 모드 여부
        """
        self.base_url = base_url
        self.username = username
        self.password = password
        self.headless = headless

        # 크롤링 상태
        self.visited_urls = set()
        self.max_depth = 2

        # 수집된 데이터
        self.all_endpoints = []
        self.all_forms = []
        self.all_links = []
        self.network_data = {}
        self.all_interaction_results = []  # 모든 페이지의 클릭 결과

        # Playwright 컴포넌트
        self.browser_controller = None
        self.network_capturer = None
        self.content_analyzer = None

    def start(self):
        """크롤러 시작 (브라우저 초기화)"""
        print(f"[+] 동적 크롤러 시작")
        print(f"    대상: {self.base_url}")

        # 브라우저 시작
        self.browser_controller = PlaywrightBrowserController(headless=self.headless)
        self.browser_controller.start_browser()

        # 네트워크 캡처 시작
        self.network_capturer = NetworkTrafficCapturer(self.browser_controller.page)

        print(f"[+] 브라우저 및 네트워크 캡처 준비 완료\n")

    # ========================================
    # 1. 로그인 자동화
    # ========================================

    def auto_login(self, login_url=None, username_selector=None, password_selector=None, submit_selector=None):
        """
        Playwright를 사용한 자동 로그인

        Args:
            login_url: 로그인 페이지 URL (None이면 base_url/login.php)
            username_selector: 사용자명 입력 필드 선택자
            password_selector: 비밀번호 입력 필드 선택자
            submit_selector: 로그인 버튼 선택자

        Returns:
            bool: 로그인 성공 여부
        """
        if not self.username or not self.password:
            print("[!] 로그인 정보가 없습니다. 로그인을 건너뜁니다.")
            return False

        print(f"[+] 자동 로그인 시작: {self.username}")

        # 기본값 설정 (DVWA 기준)
        if login_url is None:
            login_url = urljoin(self.base_url, "login.php")

        if username_selector is None:
            username_selector = 'input[name="username"]'

        if password_selector is None:
            password_selector = 'input[name="password"]'

        if submit_selector is None:
            submit_selector = 'input[type="submit"], button[type="submit"]'

        try:
            # 1. 로그인 페이지 이동
            self.browser_controller.navigate_to(login_url)

            # 2. 폼 필드 입력
            self.browser_controller.fill_input(username_selector, self.username)
            self.browser_controller.fill_input(password_selector, self.password)

            # 3. 로그인 버튼 클릭
            self.browser_controller.click_element(submit_selector)

            # 4. 페이지 로딩 대기
            self.browser_controller.wait_for_load_state('networkidle', timeout=10000)

            # 5. 로그인 성공 확인 (URL 변경 확인)
            current_url = self.browser_controller.get_current_url()

            if 'login' not in current_url.lower():
                print(f"[+] 로그인 성공! 현재 URL: {current_url}")
                return True
            else:
                print(f"[!] 로그인 실패 (여전히 로그인 페이지에 있음)")
                return False

        except Exception as e:
            print(f"[!] 로그인 에러: {e}")
            return False

    # ========================================
    # 2. 재귀적 동적 크롤링
    # ========================================

    def crawl(self, url=None, current_depth=0):
        """
        재귀적 동적 크롤링 (1~3단계 통합)

        Args:
            url: 크롤링할 URL (None이면 base_url)
            current_depth: 현재 깊이
        """
        if url is None:
            url = self.base_url

        # 방문 체크
        if url in self.visited_urls or current_depth > self.max_depth:
            return

        # 도메인 체크
        if not self._is_same_domain(url):
            return

        # 로그아웃, CAPTCHA URL 제외
        if 'logout' in url.lower() or 'captcha' in url.lower():
            return

        print(f"\n[+] 크롤링 중: {url} (깊이: {current_depth})")
        self.visited_urls.add(url)

        try:
            # 1. 페이지 이동
            self.browser_controller.navigate_to(url)

            # 2. 동적 콘텐츠 분석
            self.content_analyzer = DynamicContentAnalyzer(
                self.browser_controller.page,
                self.base_url
            )

            # DOM 분석
            self.content_analyzer.analyze_rendered_dom()

            # Lazy Loading 처리
            self.content_analyzer.handle_infinite_scroll(max_scrolls=3, scroll_pause_time=500)
            self.content_analyzer.handle_load_more_button(max_clicks=3)

            # 동적 링크/폼 추출
            links = self.content_analyzer.extract_dynamic_links()
            forms = self.content_analyzer.extract_dynamic_forms()

            # 인터랙티브 요소 추출
            self.content_analyzer.extract_all_interactive_elements()

            # 🆕 인터랙티브 요소 자동 클릭 (숨겨진 AJAX 요청 발견)
            print(f"\n[+] 버튼/드롭다운 자동 클릭으로 숨겨진 API 탐색...")
            click_results = self.content_analyzer.trigger_interactive_elements(max_clicks=15)
            print(f"    클릭한 요소: {len(click_results['clicked_elements'])}개")
            print(f"    스킵한 요소: {len(click_results['skipped_elements'])}개")

            # 클릭 결과 저장 (페이지 URL과 함께)
            if click_results['clicked_elements'] or click_results['skipped_elements']:
                self.all_interaction_results.append({
                    'page_url': url,
                    'clicked_elements': click_results['clicked_elements'],
                    'skipped_elements': click_results['skipped_elements'],
                    'errors': click_results['errors']
                })

            # SPA 라우트 감지
            self.content_analyzer.detect_spa_routes()

            # 3. 수집된 데이터 저장
            self._merge_data(url, links, forms)

            # 4. 재귀적 크롤링 (발견된 링크 탐색)
            if current_depth < self.max_depth:
                for link in links[:30]:  # 링크 개수 제한 증가 (10 -> 30)
                    next_url = link['href']
                    if next_url not in self.visited_urls:
                        self.crawl(next_url, current_depth + 1)

        except Exception as e:
            print(f"[!] 크롤링 에러: {url} - {e}")

    def _merge_data(self, url, links, forms):
        """수집된 데이터를 통합"""

        # 링크 통합
        for link in links:
            if link not in self.all_links:
                self.all_links.append(link)

        # 폼을 엔드포인트로 변환하여 저장
        for form in forms:
            endpoint = {
                'url': form['action'],
                'method': form['method'].upper(),
                'page_url': url,
                'source': 'dynamic_form',
                'parameters': []
            }

            for inp in form['inputs']:
                if inp['name']:
                    param = {
                        'name': inp['name'],
                        'type': inp['type'],
                        'location': 'body' if form['method'].upper() == 'POST' else 'query',
                        'default_value': inp['value'],
                        'required': inp['required']
                    }
                    endpoint['parameters'].append(param)

            # 중복 확인
            endpoint_key = f"{endpoint['method']}:{endpoint['url']}"
            existing_keys = [f"{e['method']}:{e['url']}" for e in self.all_endpoints]

            if endpoint_key not in existing_keys:
                self.all_endpoints.append(endpoint)
                self.all_forms.append(form)

    # ========================================
    # 3. 수집 데이터 통합 JSON 저장
    # ========================================

    def export_to_json(self, filename="integrated_crawl_results.json"):
        """
        모든 수집 데이터를 통합하여 JSON으로 저장

        Returns:
            str: 저장된 파일명
        """
        print(f"\n[+] 크롤링 결과 통합 중...")

        # 네트워크 캡처 엔드포인트 통합
        network_endpoints = self.network_capturer.get_endpoints()

        # 엔드포인트 통합 (중복 제거)
        all_endpoints = self.all_endpoints.copy()

        for net_endpoint in network_endpoints:
            endpoint_key = f"{net_endpoint['method']}:{net_endpoint['url']}"
            existing_keys = [f"{e['method']}:{e['url']}" for e in all_endpoints]

            if endpoint_key not in existing_keys:
                all_endpoints.append(net_endpoint)

        # 통합 데이터 구성
        data = {
            'crawled_at': datetime.now().isoformat(),
            'target': self.base_url,
            'statistics': {
                'pages_visited': len(self.visited_urls),
                'total_links': len(self.all_links),
                'total_forms': len(self.all_forms),
                'total_endpoints': len(all_endpoints),
                'network_requests': len(self.network_capturer.get_all_requests()),
                'ajax_requests': len(self.network_capturer.get_ajax_requests()),
                'total_clicked_elements': sum(len(r['clicked_elements']) for r in self.all_interaction_results),
                'total_skipped_elements': sum(len(r['skipped_elements']) for r in self.all_interaction_results)
            },
            'visited_urls': list(self.visited_urls),
            'endpoints': all_endpoints,
            'forms': self.all_forms,
            'links': self.all_links,
            'interaction_results': self.all_interaction_results,  # 🆕 클릭 결과 추가
            'network_capture': {
                'ajax_requests': self.network_capturer.get_ajax_requests(),
                'all_requests': self.network_capturer.get_all_requests()[:100]  # 최대 100개만
            },
            'session': {
                'cookies': {cookie['name']: cookie['value'] for cookie in self.browser_controller.context.cookies()} if self.browser_controller else {},
                'user_agent': self.browser_controller.page.evaluate('navigator.userAgent') if self.browser_controller else None
            }
        }

        # JSON 저장
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"\n[+] 통합 크롤링 결과 저장: {filename}")
        print(f"    - 방문 페이지: {len(self.visited_urls)}개")
        print(f"    - 총 엔드포인트: {len(all_endpoints)}개")
        print(f"    - 총 폼: {len(self.all_forms)}개")
        print(f"    - 총 링크: {len(self.all_links)}개")
        print(f"    - 네트워크 요청: {len(self.network_capturer.get_all_requests())}개")
        print(f"    - 클릭한 요소: {sum(len(r['clicked_elements']) for r in self.all_interaction_results)}개")
        print(f"    - 스킵한 요소: {sum(len(r['skipped_elements']) for r in self.all_interaction_results)}개")

        return filename

    def show_summary(self):
        """크롤링 결과 요약 출력"""
        print("\n" + "="*60)
        print("동적 크롤링 결과 요약")
        print("="*60)
        print(f"방문한 페이지: {len(self.visited_urls)}개")
        print(f"발견된 링크: {len(self.all_links)}개")
        print(f"발견된 폼: {len(self.all_forms)}개")
        print(f"발견된 엔드포인트: {len(self.all_endpoints)}개")

        # 네트워크 통계
        net_stats = self.network_capturer.get_statistics()
        print(f"\n네트워크 캡처:")
        print(f"  - 총 요청: {net_stats['total_requests']}개")
        print(f"  - AJAX 요청: {net_stats['ajax_requests']}개")
        print(f"  - 발견된 엔드포인트: {net_stats['endpoints_found']}개")

        # 방문한 URL 목록
        if self.visited_urls:
            print(f"\n방문한 페이지:")
            for i, url in enumerate(list(self.visited_urls)[:10], 1):
                print(f"  {i}. {url}")
            if len(self.visited_urls) > 10:
                print(f"  ... 외 {len(self.visited_urls) - 10}개")

        # 엔드포인트 요약
        if self.all_endpoints:
            print(f"\n발견된 엔드포인트:")
            for i, endpoint in enumerate(self.all_endpoints[:10], 1):
                params_count = len(endpoint['parameters'])
                print(f"  {i}. {endpoint['method']} {endpoint['url']} ({params_count}개 파라미터)")
            if len(self.all_endpoints) > 10:
                print(f"  ... 외 {len(self.all_endpoints) - 10}개")

        print("="*60)

    # ========================================
    # 유틸리티 메서드
    # ========================================

    def _is_same_domain(self, url):
        """같은 도메인인지 확인"""
        try:
            return urlparse(url).netloc == urlparse(self.base_url).netloc
        except:
            return False

    def set_max_depth(self, depth):
        """최대 크롤링 깊이 설정"""
        self.max_depth = depth
        print(f"[+] 최대 크롤링 깊이 설정: {depth}")

    def close(self):
        """브라우저 종료"""
        if self.browser_controller:
            self.browser_controller.close()
        print("[+] 크롤러 종료")


# 사용 예제
if __name__ == "__main__":
    # DVWA 설정
    DVWA_URL = "http://192.168.204.128/dvwa/"  # 본인의 DVWA URL로 변경
    USERNAME = "admin"
    PASSWORD = "password"

    print("="*60)
    print("동적 크롤러 시작 (Playwright 기반)")
    print("="*60)

    # 1~4단계 통합 크롤러 생성
    crawler = AutomatedDynamicCrawler(
        base_url=DVWA_URL,
        username=USERNAME,
        password=PASSWORD,
        headless=True  # True: 브라우저 숨김, False: 브라우저 보임
    )

    try:
        # 1. 브라우저 시작
        crawler.start()

        # 2. 자동 로그인
        if crawler.auto_login():
            # 3. 재귀적 동적 크롤링 (깊이 2)
            crawler.set_max_depth(2)
            crawler.crawl()

            # 4. 결과 출력
            crawler.show_summary()

            # 5. 통합 JSON 저장
            crawler.export_to_json("dynamic_crawl_results.json")
        else:
            print("[!] 로그인 실패. 크롤링을 건너뜁니다.")

    except Exception as e:
        print(f"[!] 크롤링 중 에러 발생: {e}")

    finally:
        # 6. 브라우저 종료
        crawler.close()

    print("\n[+] 크롤링 완료!")