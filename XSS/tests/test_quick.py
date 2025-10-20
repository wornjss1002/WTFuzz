"""
XSS Fuzzer Quick Test
=====================

Module import and basic functionality test
"""

import sys
from pathlib import Path

# Add common model path
sys.path.insert(0, str(Path(__file__).parent.parent))

print("=" * 60)
print("XSS Fuzzer Module Test")
print("=" * 60)

# 1. Common model import test
print("\n[1] Common model import test...")
try:
    from common.models import (
        Endpoint, Parameter, HTTPMethod, ParameterType,
        XSSTestResult, ConfidenceLevel, VulnerabilityType
    )
    print("[OK] Common model import success")
except Exception as e:
    print(f"[FAIL] Common model import failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# 2. XSS module import test
print("\n[2] XSS module import test...")
try:
    from src.modules.input_handler import InputHandler
    from src.modules.payload_generator import PayloadGenerator, PayloadLevel
    print("[OK] XSS module import success")
except Exception as e:
    print(f"[FAIL] XSS module import failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# 3. Load example crawler output
print("\n[3] Load example crawler output test...")
try:
    example_file = "examples/crawler_output_example.json"
    endpoints = InputHandler.from_json_file(example_file)
    print(f"[OK] Loaded {len(endpoints)} endpoints")

    for i, ep in enumerate(endpoints, 1):
        print(f"\n  Endpoint {i}:")
        print(f"    - URL: {ep.url}")
        print(f"    - Method: {ep.method.value}")
        print(f"    - Parameters: {len(ep.parameters)}")

        # Check testable parameters
        testable = InputHandler.get_testable_parameters(ep)
        print(f"    - Testable: {len(testable)}")
        for param in testable:
            print(f"      * {param.name} ({param.param_type.value})")

except Exception as e:
    print(f"[FAIL] Crawler output load failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# 4. Payload generator test
print("\n[4] Payload generator test...")
try:
    payload_gen = PayloadGenerator()

    for level in [PayloadLevel.LEVEL_1, PayloadLevel.LEVEL_2]:
        payloads = payload_gen.get_payloads_by_level(level)
        print(f"  - Level {level.value}: {len(payloads)} payloads")

        # Show first 3 payload samples
        for payload in payloads[:3]:
            preview = payload.payload[:50] if len(payload.payload) > 50 else payload.payload
            print(f"    * [{payload.id}] {preview}...")

    print("[OK] Payload generator test success")

except Exception as e:
    print(f"[FAIL] Payload generator failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# 5. URL build test
print("\n[5] Test URL build validation...")
try:
    if endpoints:
        ep = endpoints[0]
        testable = InputHandler.get_testable_parameters(ep)

        if testable:
            param = testable[0]
            test_payload = "<script>alert(1)</script>"
            test_url = InputHandler.build_test_url(ep, param.name, test_payload)

            print(f"  Original URL: {ep.url}")
            print(f"  Parameter: {param.name}")
            print(f"  Payload: {test_payload}")
            print(f"  Test URL: {test_url}")
            print("[OK] URL build success")
        else:
            print("  [WARN] No testable parameters")

except Exception as e:
    print(f"[FAIL] URL build failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n" + "=" * 60)
print("[OK] All basic tests passed!")
print("=" * 60)
print("\nNext steps: Install playwright and test detection engine")
print("  pip install playwright")
print("  playwright install chromium")
print("  python xss_fuzzer.py -i examples/crawler_output_example.json --headless")
