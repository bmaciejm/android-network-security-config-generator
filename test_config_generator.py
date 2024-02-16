import unittest
from argparse import Namespace
from config_generator import ConfigGenerator


class MyTestCase(unittest.TestCase):
    def test_initialization(self):
        domains = ["example.com", "test.com"]
        generator = ConfigGenerator()
        self.assertEqual(True, False)  # add assertion here


# test script not the class https://stackoverflow.com/questions/18160078/how-do-you-write-tests-for-the-argparse-portion-of-a-python-module

if __name__ == '__main__':
    unittest.main()
