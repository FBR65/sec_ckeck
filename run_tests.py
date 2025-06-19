#!/usr/bin/env python3
"""
Main test runner for security testing agent.
"""

import asyncio
import subprocess
import time
import os
import sys
from pathlib import Path


def check_docker():
    """Check if Docker is available."""
    try:
        result = subprocess.run(["docker", "--version"], capture_output=True, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False


def start_test_environment():
    """Start the Docker test environment."""
    print("Starting test environment...")
    test_dir = Path(__file__).parent / "test"

    if not test_dir.exists():
        print(f"Error: Test directory not found at {test_dir}")
        return False

    os.chdir(test_dir)

    # Start containers
    result = subprocess.run(
        ["docker-compose", "up", "-d"], capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"Failed to start containers: {result.stderr}")
        return False

    print("Waiting for services to start...")
    time.sleep(30)  # Wait for services to be ready

    return True


def stop_test_environment():
    """Stop the Docker test environment."""
    print("Stopping test environment...")
    test_dir = Path(__file__).parent / "test"
    os.chdir(test_dir)

    subprocess.run(["docker-compose", "down"], capture_output=True)
    print("Test environment stopped.")


async def run_security_tests():
    """Run the security test suite."""
    print("\nRunning security tests...")
    test_dir = Path(__file__).parent / "test"

    # Import and run test scenarios
    sys.path.insert(0, str(test_dir))
    from test_scenarios import SecurityTestSuite

    test_suite = SecurityTestSuite()
    await test_suite.run_all_tests()


def main():
    """Main test execution."""
    print("Security Testing Agent - Test Runner")
    print("=" * 40)

    # Check prerequisites
    if not check_docker():
        print("Error: Docker is not available. Please install Docker first.")
        return 1

    try:
        # Start test environment
        if not start_test_environment():
            return 1

        # Run tests
        asyncio.run(run_security_tests())

        return 0

    except KeyboardInterrupt:
        print("\nTest interrupted by user.")
        return 1
    except Exception as e:
        print(f"Test failed with error: {e}")
        return 1
    finally:
        # Always cleanup
        stop_test_environment()


if __name__ == "__main__":
    sys.exit(main())
