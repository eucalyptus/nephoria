import unittest
from nephoria.testcontroller import TestController

class NephoriaUnitTest(unittest.TestCase):
    def setUp(self):
        self.tester = TestController()

    def test_logger(self):
        self.assertNotEqual(self.tester.log, None)

if __name__ == "__main__":
    unittest.main()