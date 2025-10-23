"""
Genetic Fuzzer: 유전 알고리즘 기반 XSS 페이로드 진화

KameleonFuzz 방식의 진화 알고리즘을 적용하여
WAF 우회와 XSS 성공률을 높이는 페이로드를 생성합니다.

참고: KameleonFuzz (2014) - Evolutionary Fuzzing with Attack Grammar
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Callable, Tuple
import random
import time
from copy import deepcopy

# 기존 모듈 임포트
from payload_generator import PayloadMutator, PayloadEncoder


@dataclass
class Individual:
    """
    개체 (유전 알고리즘의 한 개체)

    하나의 페이로드와 그 적합도를 나타냅니다.
    """
    payload: str
    fitness: float = 0.0
    generation: int = 0
    context_type: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    # 성능 메트릭
    waf_bypassed: bool = False
    http_200: bool = False
    reflected: bool = False
    xss_executed: bool = False

    def __repr__(self):
        return f"Individual(gen={self.generation}, fitness={self.fitness:.2f}, payload='{self.payload[:30]}...')"

    def calculate_fitness(self):
        """
        적합도 계산

        Fitness = WAF우회×5 + HTTP200×3 + 반사×4 + XSS실행×10

        참고: KameleonFuzz 논문의 fitness function
        """
        score = 0.0

        if self.waf_bypassed:
            score += 5.0

        if self.http_200:
            score += 3.0

        if self.reflected:
            score += 4.0

        if self.xss_executed:
            score += 10.0

        # 페이로드 길이 페널티 (짧을수록 좋음)
        length_penalty = len(self.payload) / 1000.0
        score -= length_penalty

        self.fitness = max(0.0, score)
        return self.fitness


@dataclass
class Population:
    """
    집단 (여러 개체의 모음)
    """
    individuals: List[Individual] = field(default_factory=list)
    generation: int = 0
    max_size: int = 50

    def __len__(self):
        return len(self.individuals)

    def add(self, individual: Individual):
        """개체 추가"""
        individual.generation = self.generation
        self.individuals.append(individual)

    def sort_by_fitness(self):
        """적합도 순으로 정렬 (내림차순)"""
        self.individuals.sort(key=lambda x: x.fitness, reverse=True)

    def get_top_n(self, n: int) -> List[Individual]:
        """상위 N개 개체 반환"""
        self.sort_by_fitness()
        return self.individuals[:n]

    def get_best(self) -> Optional[Individual]:
        """가장 적합한 개체 반환"""
        if not self.individuals:
            return None
        return max(self.individuals, key=lambda x: x.fitness)

    def get_average_fitness(self) -> float:
        """평균 적합도"""
        if not self.individuals:
            return 0.0
        return sum(ind.fitness for ind in self.individuals) / len(self.individuals)


class GeneticOperators:
    """
    유전 연산자 모음

    - Selection (선택)
    - Crossover (교배)
    - Mutation (변이)
    """

    @staticmethod
    def tournament_selection(
        population: Population,
        tournament_size: int = 3
    ) -> Individual:
        """
        토너먼트 선택

        무작위로 N개를 뽑아 그 중 가장 적합한 개체를 선택

        Args:
            population: 전체 집단
            tournament_size: 토너먼트 크기 (보통 3~5)

        Returns:
            선택된 개체
        """
        if len(population) < tournament_size:
            tournament_size = len(population)

        # 무작위로 tournament_size개 선택
        candidates = random.sample(population.individuals, tournament_size)

        # 가장 적합한 개체 반환
        return max(candidates, key=lambda x: x.fitness)

    @staticmethod
    def single_point_crossover(
        parent1: Individual,
        parent2: Individual
    ) -> Tuple[Individual, Individual]:
        """
        단일 지점 교배

        두 부모의 페이로드를 한 지점에서 교차하여 자식 생성

        예:
            parent1: "<img src=x onerror=alert(1)>"
            parent2: "<svg onload=prompt(2)>"

            자식1: "<img src=x onerror=prompt(2)>"
            자식2: "<svg onload=alert(1)>"

        Args:
            parent1, parent2: 부모 개체

        Returns:
            (자식1, 자식2)
        """
        p1_payload = parent1.payload
        p2_payload = parent2.payload

        # 교차 지점 선택 (짧은 쪽 기준)
        min_len = min(len(p1_payload), len(p2_payload))
        if min_len <= 1:
            # 교차 불가능 - 부모 그대로 복제
            return deepcopy(parent1), deepcopy(parent2)

        crossover_point = random.randint(1, min_len - 1)

        # 자식 생성
        child1_payload = p1_payload[:crossover_point] + p2_payload[crossover_point:]
        child2_payload = p2_payload[:crossover_point] + p1_payload[crossover_point:]

        child1 = Individual(
            payload=child1_payload,
            context_type=parent1.context_type,
            metadata={'parents': [parent1.payload[:20], parent2.payload[:20]]}
        )

        child2 = Individual(
            payload=child2_payload,
            context_type=parent2.context_type,
            metadata={'parents': [parent2.payload[:20], parent1.payload[:20]]}
        )

        return child1, child2

    @staticmethod
    def uniform_crossover(
        parent1: Individual,
        parent2: Individual,
        mix_ratio: float = 0.5
    ) -> Individual:
        """
        균등 교배

        각 문자를 mix_ratio 확률로 parent1 또는 parent2에서 선택

        Args:
            parent1, parent2: 부모 개체
            mix_ratio: parent1 선택 확률

        Returns:
            자식 개체
        """
        p1_payload = parent1.payload
        p2_payload = parent2.payload

        min_len = min(len(p1_payload), len(p2_payload))
        max_len = max(len(p1_payload), len(p2_payload))

        child_payload = ""

        for i in range(max_len):
            if i < min_len:
                # 두 부모 모두 해당 위치에 문자가 있음
                if random.random() < mix_ratio:
                    child_payload += p1_payload[i]
                else:
                    child_payload += p2_payload[i]
            elif i < len(p1_payload):
                # parent1만 남은 부분
                child_payload += p1_payload[i]
            else:
                # parent2만 남은 부분
                child_payload += p2_payload[i]

        child = Individual(
            payload=child_payload,
            context_type=parent1.context_type,
            metadata={'parents': [parent1.payload[:20], parent2.payload[:20]]}
        )

        return child

    @staticmethod
    def mutate(
        individual: Individual,
        mutation_rate: float = 0.3
    ) -> Individual:
        """
        변이

        PayloadMutator를 사용하여 페이로드 변형

        Args:
            individual: 변이시킬 개체
            mutation_rate: 변이 확률 (0.0~1.0)

        Returns:
            변이된 개체
        """
        if random.random() > mutation_rate:
            # 변이 안 함
            return deepcopy(individual)

        # 변이 기법 선택
        mutation_types = [
            'case_variation',
            'comment_insertion',
            'null_bytes',
            'character_substitution'
        ]

        mutation_type = random.choice(mutation_types)
        mutated_payload = individual.payload

        if mutation_type == 'case_variation':
            result = PayloadMutator.case_variation(individual.payload)
            mutated_payload = random.choice(result) if isinstance(result, list) else result
        elif mutation_type == 'comment_insertion':
            result = PayloadMutator.add_comments(individual.payload)
            mutated_payload = random.choice(result) if isinstance(result, list) else result
        elif mutation_type == 'null_bytes':
            result = PayloadMutator.add_null_bytes(individual.payload)
            mutated_payload = random.choice(result) if isinstance(result, list) else result
        elif mutation_type == 'character_substitution':
            result = PayloadMutator.character_substitution(individual.payload)
            mutated_payload = random.choice(result) if isinstance(result, list) else result

        mutated = Individual(
            payload=mutated_payload,
            context_type=individual.context_type,
            metadata={
                'mutation': mutation_type,
                'original': individual.payload[:20]
            }
        )

        return mutated


class GeneticFuzzer:
    """
    유전 알고리즘 기반 XSS 퍼저

    진화 프로세스:
    1. 초기 집단 생성 (seed payloads)
    2. 적합도 평가 (fitness evaluation)
    3. 선택 (selection)
    4. 교배 (crossover)
    5. 변이 (mutation)
    6. 다음 세대로 반복
    """

    def __init__(
        self,
        population_size: int = 50,
        max_generations: int = 50,
        mutation_rate: float = 0.3,
        crossover_rate: float = 0.7,
        elitism_count: int = 5
    ):
        """
        Args:
            population_size: 집단 크기
            max_generations: 최대 세대 수
            mutation_rate: 변이 확률
            crossover_rate: 교배 확률
            elitism_count: 엘리트 보존 개수 (상위 N개는 무조건 다음 세대로)
        """
        self.population_size = population_size
        self.max_generations = max_generations
        self.mutation_rate = mutation_rate
        self.crossover_rate = crossover_rate
        self.elitism_count = elitism_count

        self.current_population = Population(max_size=population_size)
        self.best_individual: Optional[Individual] = None
        self.history: List[Dict[str, Any]] = []

        # 통계
        self.stats = {
            'total_evaluations': 0,
            'successful_xss': 0,
            'waf_bypasses': 0
        }

    def initialize_population(self, seed_payloads: List[str], context_type: str = 'html_body'):
        """
        초기 집단 생성

        Args:
            seed_payloads: 초기 페이로드 리스트
            context_type: 컨텍스트 타입
        """
        self.current_population = Population(max_size=self.population_size)

        for payload in seed_payloads[:self.population_size]:
            individual = Individual(
                payload=payload,
                generation=0,
                context_type=context_type
            )
            self.current_population.add(individual)

        # 나머지를 변이로 채우기
        while len(self.current_population) < self.population_size:
            base = random.choice(self.current_population.individuals)
            mutated = GeneticOperators.mutate(base, mutation_rate=0.5)
            self.current_population.add(mutated)

    def evaluate_fitness(
        self,
        evaluation_function: Callable[[Individual], Individual]
    ):
        """
        집단의 모든 개체 적합도 평가

        Args:
            evaluation_function: 개체를 받아 평가 후 반환하는 함수
                예: lambda ind: evaluate_on_server(ind)
        """
        for individual in self.current_population.individuals:
            # 이미 평가된 개체는 건너뛰기
            if individual.fitness > 0:
                continue

            # 평가 함수 실행
            evaluated = evaluation_function(individual)

            # 결과 업데이트
            individual.waf_bypassed = evaluated.waf_bypassed
            individual.http_200 = evaluated.http_200
            individual.reflected = evaluated.reflected
            individual.xss_executed = evaluated.xss_executed

            # 적합도 계산
            individual.calculate_fitness()

            self.stats['total_evaluations'] += 1
            if individual.xss_executed:
                self.stats['successful_xss'] += 1
            if individual.waf_bypassed:
                self.stats['waf_bypasses'] += 1

        # 최고 개체 업데이트
        best = self.current_population.get_best()
        if best and (self.best_individual is None or best.fitness > self.best_individual.fitness):
            self.best_individual = deepcopy(best)

    def evolve_one_generation(self):
        """
        한 세대 진화

        1. 선택 (Selection)
        2. 교배 (Crossover)
        3. 변이 (Mutation)
        4. 다음 세대 구성
        """
        old_population = self.current_population
        new_population = Population(max_size=self.population_size)
        new_population.generation = old_population.generation + 1

        # 1. 엘리트 보존 (Elitism)
        elite = old_population.get_top_n(self.elitism_count)
        for ind in elite:
            new_population.add(deepcopy(ind))

        # 2. 나머지를 선택, 교배, 변이로 채우기
        while len(new_population) < self.population_size:
            # 2-1. 부모 선택 (Tournament Selection)
            parent1 = GeneticOperators.tournament_selection(old_population)
            parent2 = GeneticOperators.tournament_selection(old_population)

            # 2-2. 교배 (Crossover)
            if random.random() < self.crossover_rate:
                child1, child2 = GeneticOperators.single_point_crossover(parent1, parent2)
            else:
                # 교배 안 함 - 부모 복제
                child1, child2 = deepcopy(parent1), deepcopy(parent2)

            # 2-3. 변이 (Mutation)
            child1 = GeneticOperators.mutate(child1, self.mutation_rate)
            child2 = GeneticOperators.mutate(child2, self.mutation_rate)

            # 2-4. 새 집단에 추가
            new_population.add(child1)
            if len(new_population) < self.population_size:
                new_population.add(child2)

        self.current_population = new_population

    def run(
        self,
        seed_payloads: List[str],
        evaluation_function: Callable[[Individual], Individual],
        context_type: str = 'html_body',
        verbose: bool = True
    ) -> Individual:
        """
        유전 알고리즘 실행

        Args:
            seed_payloads: 초기 페이로드
            evaluation_function: 적합도 평가 함수
            context_type: 컨텍스트 타입
            verbose: 진행 상황 출력 여부

        Returns:
            가장 적합한 개체
        """
        # 초기화
        self.initialize_population(seed_payloads, context_type)

        if verbose:
            print(f"\n{'='*60}")
            print(f"Genetic Fuzzer - Evolutionary XSS Payload Optimization")
            print(f"{'='*60}\n")
            print(f"Population Size: {self.population_size}")
            print(f"Max Generations: {self.max_generations}")
            print(f"Mutation Rate: {self.mutation_rate}")
            print(f"Crossover Rate: {self.crossover_rate}")
            print(f"Elitism Count: {self.elitism_count}")
            print(f"\nStarting evolution...\n")

        # 초기 집단 평가
        self.evaluate_fitness(evaluation_function)

        # 진화 루프
        for generation in range(1, self.max_generations + 1):
            # 한 세대 진화
            self.evolve_one_generation()

            # 적합도 평가
            self.evaluate_fitness(evaluation_function)

            # 통계 기록
            best = self.current_population.get_best()
            avg_fitness = self.current_population.get_average_fitness()

            self.history.append({
                'generation': generation,
                'best_fitness': best.fitness if best else 0,
                'avg_fitness': avg_fitness,
                'best_payload': best.payload if best else ''
            })

            # 진행 상황 출력
            if verbose and generation % 5 == 0:
                print(f"[Gen {generation:2d}/{self.max_generations}] "
                      f"Best Fitness: {best.fitness:.2f} | "
                      f"Avg Fitness: {avg_fitness:.2f} | "
                      f"XSS: {self.stats['successful_xss']} | "
                      f"WAF Bypass: {self.stats['waf_bypasses']}")

            # 조기 종료 조건: 완벽한 페이로드 발견
            if best and best.fitness >= 20.0:  # WAF(5) + 200(3) + 반사(4) + XSS(10) = 22
                if verbose:
                    print(f"\n[!] Perfect payload found at generation {generation}!")
                break

        # 최종 결과
        if verbose:
            print(f"\n{'='*60}")
            print("Evolution Complete!")
            print(f"{'='*60}\n")
            print(f"Total Evaluations: {self.stats['total_evaluations']}")
            print(f"Successful XSS: {self.stats['successful_xss']}")
            print(f"WAF Bypasses: {self.stats['waf_bypasses']}")

            if self.best_individual:
                print(f"\nBest Individual:")
                print(f"  Generation: {self.best_individual.generation}")
                print(f"  Fitness: {self.best_individual.fitness:.2f}")
                print(f"  Payload: {self.best_individual.payload}")
                print(f"  WAF Bypassed: {self.best_individual.waf_bypassed}")
                print(f"  XSS Executed: {self.best_individual.xss_executed}")

        return self.best_individual


# ========================================
# 유틸리티 함수
# ========================================

def dummy_evaluation_function(individual: Individual) -> Individual:
    """
    더미 평가 함수 (테스트용)

    실제로는 서버에 페이로드를 전송하고 결과를 확인해야 합니다.
    """
    # 랜덤으로 성공/실패 시뮬레이션
    individual.waf_bypassed = random.random() > 0.5
    individual.http_200 = random.random() > 0.3
    individual.reflected = random.random() > 0.4
    individual.xss_executed = random.random() > 0.6

    individual.calculate_fitness()
    return individual


if __name__ == "__main__":
    """
    간단한 테스트 실행
    """
    print("""
Genetic Fuzzer Module

Usage:
    from genetic_fuzzer import GeneticFuzzer, Individual
    from payload_generator import PayloadGenerator

    # 초기 페이로드 생성
    generator = PayloadGenerator()
    seed_payloads = [p.payload for p in generator.generate_for_context('html_body')]

    # 퍼저 초기화
    fuzzer = GeneticFuzzer(
        population_size=30,
        max_generations=20,
        mutation_rate=0.3,
        crossover_rate=0.7
    )

    # 평가 함수 정의 (실제 서버 테스트)
    def evaluate(individual):
        # 서버에 페이로드 전송
        # 결과에 따라 individual.waf_bypassed, http_200 등 설정
        return individual

    # 진화 실행
    best = fuzzer.run(seed_payloads, evaluate)

For detailed examples, see tests/test_genetic_fuzzer.py
""")

    # 간단한 데모
    print("\n[Demo] Running genetic algorithm with dummy evaluation...")

    seed = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>"
    ]

    fuzzer = GeneticFuzzer(
        population_size=10,
        max_generations=10,
        mutation_rate=0.3
    )

    best = fuzzer.run(seed, dummy_evaluation_function, verbose=True)

    print(f"\n[Demo Complete]")
