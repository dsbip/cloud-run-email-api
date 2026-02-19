"""
Test runner script with various test execution options.
Run this script to execute tests with different configurations.
"""
import sys
import subprocess


def run_all_tests():
    """Run all tests with coverage."""
    print("Running all tests with coverage...\n")
    result = subprocess.run([
        sys.executable, "-m", "pytest",
        "test_main.py",
        "-v",
        "--cov=.",
        "--cov-report=term-missing",
        "--cov-report=html"
    ])
    return result.returncode


def run_unit_tests():
    """Run only unit tests."""
    print("Running unit tests...\n")
    result = subprocess.run([
        sys.executable, "-m", "pytest",
        "test_main.py",
        "-v",
        "-m", "unit"
    ])
    return result.returncode


def run_quick_tests():
    """Run tests quickly without coverage."""
    print("Running quick tests (no coverage)...\n")
    result = subprocess.run([
        sys.executable, "-m", "pytest",
        "test_main.py",
        "-v",
        "--tb=short"
    ])
    return result.returncode


def run_specific_class(class_name: str):
    """Run tests from a specific test class."""
    print(f"Running tests from {class_name}...\n")
    result = subprocess.run([
        sys.executable, "-m", "pytest",
        "test_main.py",
        "-v",
        "-k", class_name
    ])
    return result.returncode


def run_with_output():
    """Run tests with detailed output."""
    print("Running tests with detailed output...\n")
    result = subprocess.run([
        sys.executable, "-m", "pytest",
        "test_main.py",
        "-vv",
        "-s",
        "--tb=long"
    ])
    return result.returncode


def main():
    """Main test runner with menu."""
    print("=" * 50)
    print("Email Sending API - Test Runner")
    print("=" * 50)
    print("\nOptions:")
    print("1. Run all tests with coverage (recommended)")
    print("2. Run unit tests only")
    print("3. Run quick tests (no coverage)")
    print("4. Run specific test class")
    print("5. Run with detailed output")
    print("6. Exit")
    print()

    choice = input("Select option (1-6): ").strip()

    if choice == "1":
        exit_code = run_all_tests()
    elif choice == "2":
        exit_code = run_unit_tests()
    elif choice == "3":
        exit_code = run_quick_tests()
    elif choice == "4":
        class_name = input("Enter test class name (e.g., TestEmailValidation): ").strip()
        exit_code = run_specific_class(class_name)
    elif choice == "5":
        exit_code = run_with_output()
    elif choice == "6":
        print("Exiting...")
        return 0
    else:
        print("Invalid option. Running all tests by default...")
        exit_code = run_all_tests()

    print("\n" + "=" * 50)
    if exit_code == 0:
        print("✓ All tests passed!")
    else:
        print("✗ Some tests failed.")
    print("=" * 50)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
