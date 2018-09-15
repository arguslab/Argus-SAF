import unittest
import nativedroid


class TestSourceAndSinkManager(unittest.TestCase):
    def test_sasfile_parse(self):
        ssm = nativedroid.SourceAndSinkManager("src/test/resources/NativeSourcesAndSinks.txt")

if __name__ == '__main__':
    print('\nRunning ' + __file__)
    unittest.main()
