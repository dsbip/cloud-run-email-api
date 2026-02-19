"""
Integration tests against a running Docker container.
Run with: python test_live_service.py

Expects the service running at http://localhost:8080.
These tests only validate endpoints that don't require real Firestore/SendGrid.
"""
import requests
import sys

BASE_URL = "http://localhost:8080"
passed = 0
failed = 0


def test(name, func):
    global passed, failed
    try:
        func()
        print(f"  PASS: {name}")
        passed += 1
    except AssertionError as e:
        print(f"  FAIL: {name} - {e}")
        failed += 1
    except Exception as e:
        print(f"  ERROR: {name} - {type(e).__name__}: {e}")
        failed += 1


# ---- Health & Root Endpoints ----

def test_root():
    r = requests.get(f"{BASE_URL}/")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    data = r.json()
    assert data["status"] == "healthy", f"Unexpected status: {data}"
    assert "service" in data

def test_health():
    r = requests.get(f"{BASE_URL}/health")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    assert r.json()["status"] == "healthy"

# ---- Input Validation (Pydantic - no external deps needed) ----

def test_empty_to_list():
    r = requests.post(f"{BASE_URL}/send-email", json={
        "to_list": [], "cc_list": [], "mail_body": "<p>Test</p>"
    })
    assert r.status_code == 422, f"Expected 422, got {r.status_code}"

def test_invalid_email_in_to_list():
    r = requests.post(f"{BASE_URL}/send-email", json={
        "to_list": ["not-an-email"], "cc_list": [], "mail_body": "<p>Test</p>"
    })
    assert r.status_code == 422, f"Expected 422, got {r.status_code}"

def test_invalid_email_in_cc_list():
    r = requests.post(f"{BASE_URL}/send-email", json={
        "to_list": ["valid@example.com"], "cc_list": ["bad-email"], "mail_body": "<p>Test</p>"
    })
    assert r.status_code == 422, f"Expected 422, got {r.status_code}"

def test_empty_mail_body():
    r = requests.post(f"{BASE_URL}/send-email", json={
        "to_list": ["valid@example.com"], "cc_list": [], "mail_body": ""
    })
    assert r.status_code == 422, f"Expected 422, got {r.status_code}"

def test_whitespace_only_mail_body():
    r = requests.post(f"{BASE_URL}/send-email", json={
        "to_list": ["valid@example.com"], "cc_list": [], "mail_body": "   "
    })
    assert r.status_code == 422, f"Expected 422, got {r.status_code}"

def test_missing_to_list():
    r = requests.post(f"{BASE_URL}/send-email", json={
        "cc_list": [], "mail_body": "<p>Test</p>"
    })
    assert r.status_code == 422, f"Expected 422, got {r.status_code}"

def test_missing_mail_body():
    r = requests.post(f"{BASE_URL}/send-email", json={
        "to_list": ["valid@example.com"], "cc_list": []
    })
    assert r.status_code == 422, f"Expected 422, got {r.status_code}"

def test_invalid_json():
    r = requests.post(f"{BASE_URL}/send-email",
                      data="not json",
                      headers={"Content-Type": "application/json"})
    assert r.status_code == 422, f"Expected 422, got {r.status_code}"

def test_wrong_content_type():
    r = requests.post(f"{BASE_URL}/send-email",
                      data="to_list=test@example.com",
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 422, f"Expected 422, got {r.status_code}"

def test_multiple_invalid_emails():
    r = requests.post(f"{BASE_URL}/send-email", json={
        "to_list": ["bad1", "bad2@", "@bad3.com"],
        "cc_list": [],
        "mail_body": "<p>Test</p>"
    })
    assert r.status_code == 422, f"Expected 422, got {r.status_code}"

def test_cc_list_optional():
    """cc_list should default to empty when not provided."""
    r = requests.post(f"{BASE_URL}/send-email", json={
        "to_list": ["valid@example.com"],
        "mail_body": "<p>Test</p>"
    })
    # This will hit Firestore (which will fail in Docker without creds),
    # but it should NOT fail with 422 validation error
    assert r.status_code != 422, f"cc_list should be optional, got 422"

# ---- Firestore Dependency Tests ----
# The container has no real Firestore credentials, so valid email requests
# should fail at the Firestore step with 500, not at validation with 422.

def test_valid_request_hits_firestore():
    """A valid request should pass validation but fail at Firestore (no creds in container)."""
    r = requests.post(f"{BASE_URL}/send-email", json={
        "to_list": ["user@example.com"],
        "cc_list": ["cc@example.com"],
        "mail_body": "<h1>Hello</h1><p>World</p>"
    })
    # Should get past validation (not 422) and fail at Firestore (500)
    assert r.status_code == 500, f"Expected 500 (Firestore fail), got {r.status_code}"
    assert "blocked" in r.json()["detail"].lower() or "firestore" in r.json()["detail"].lower() or "fetch" in r.json()["detail"].lower(), \
        f"Expected Firestore error, got: {r.json()['detail']}"

# ---- Non-existent Endpoints ----

def test_404_unknown_endpoint():
    r = requests.get(f"{BASE_URL}/nonexistent")
    assert r.status_code == 404, f"Expected 404, got {r.status_code}"

def test_method_not_allowed():
    r = requests.get(f"{BASE_URL}/send-email")
    assert r.status_code == 405, f"Expected 405, got {r.status_code}"


if __name__ == "__main__":
    print(f"\nRunning integration tests against {BASE_URL}\n")

    # Check service is up
    try:
        requests.get(f"{BASE_URL}/health", timeout=5)
    except requests.ConnectionError:
        print(f"ERROR: Service not reachable at {BASE_URL}")
        print("Start the container first: docker run -d -p 8080:8080 ...")
        sys.exit(1)

    print("--- Health & Root ---")
    test("Root endpoint", test_root)
    test("Health endpoint", test_health)

    print("\n--- Input Validation ---")
    test("Empty to_list", test_empty_to_list)
    test("Invalid email in to_list", test_invalid_email_in_to_list)
    test("Invalid email in cc_list", test_invalid_email_in_cc_list)
    test("Empty mail_body", test_empty_mail_body)
    test("Whitespace-only mail_body", test_whitespace_only_mail_body)
    test("Missing to_list field", test_missing_to_list)
    test("Missing mail_body field", test_missing_mail_body)
    test("Invalid JSON body", test_invalid_json)
    test("Wrong content type", test_wrong_content_type)
    test("Multiple invalid emails", test_multiple_invalid_emails)
    test("cc_list is optional", test_cc_list_optional)

    print("\n--- Firestore Dependency ---")
    test("Valid request hits Firestore (fails without creds)", test_valid_request_hits_firestore)

    print("\n--- Routing ---")
    test("404 for unknown endpoint", test_404_unknown_endpoint)
    test("405 for GET on POST endpoint", test_method_not_allowed)

    print(f"\n{'='*40}")
    print(f"Results: {passed} passed, {failed} failed, {passed + failed} total")
    print(f"{'='*40}\n")

    sys.exit(1 if failed else 0)
