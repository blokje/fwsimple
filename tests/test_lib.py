import unittest
import sys
import os
import importlib # Needed for _load_class testing

# Adjust path to import fwsimple
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from fwsimple import lib

# Helper class for testing _load_class
class DummyClassForTest:
    pass

class TestLib(unittest.TestCase):

    def test_load_class_valid(self):
        # To test _load_class, we need a module and class it can import.
        # We can use this test file itself as a module, and DummyClassForTest.
        # Note: This assumes the test runner can handle this.
        # The classname should be like 'tests.test_lib.DummyClassForTest'
        # We need to ensure 'tests' is discoverable as a package.
        # For simplicity, let's try to load something from a standard library first if possible,
        # or mock importlib.import_module.

        # Attempting to load a known class from a standard library
        try:
            loaded_class = lib._load_class("collections.UserList")
            from collections import UserList
            self.assertIs(loaded_class, UserList)
        except ImportError:
            self.skipTest("Could not import collections.UserList for testing _load_class.")
        except Exception as e:
            self.fail("_load_class failed with an unexpected error: {0}".format(e))

    def test_load_class_invalid_module(self):
        with self.assertRaises(ImportError):
            lib._load_class("nonexistentmodule.NonExistentClass")

    def test_load_class_invalid_class(self):
        with self.assertRaises(AttributeError):
            lib._load_class("collections.NonExistentClassInCollections")

if __name__ == '__main__':
    # Create a dummy module for testing _load_class if needed,
    # though direct standard library import is preferred.
    # This current file can act as 'tests.test_lib' if tests is a package.
    unittest.main()
