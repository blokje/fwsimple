import unittest
import sys

if __name__ == "__main__":
    # Discover tests in the 'tests' directory
    # It will look for files named test*.py
    loader = unittest.TestLoader()
    suite = loader.discover('tests')

    # Create a text-based test runner
    runner = unittest.TextTestRunner(verbosity=2) # verbosity=2 provides more detailed output

    # Run the tests
    result = runner.run(suite)

    # Exit with an appropriate code: 0 for success, 1 for failure
    if result.wasSuccessful():
        sys.exit(0)
    else:
        sys.exit(1)
