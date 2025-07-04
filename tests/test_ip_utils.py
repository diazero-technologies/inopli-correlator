import unittest
from utils.ip_utils import is_public_ip

class TestIsPublicIP(unittest.TestCase):
    def test_public_ips(self):
        self.assertTrue(is_public_ip('8.8.8.8'))
        self.assertTrue(is_public_ip('1.1.1.1'))
        self.assertTrue(is_public_ip('2001:4860:4860::8888'))

    def test_private_ips(self):
        self.assertFalse(is_public_ip('192.168.1.1'))
        self.assertFalse(is_public_ip('10.0.0.1'))
        self.assertFalse(is_public_ip('172.16.0.1'))
        self.assertFalse(is_public_ip('127.0.0.1'))
        self.assertFalse(is_public_ip('::1'))
        self.assertFalse(is_public_ip('169.254.1.1'))
        self.assertFalse(is_public_ip('fc00::1'))

    def test_invalid_ips(self):
        self.assertFalse(is_public_ip('not.an.ip'))
        self.assertFalse(is_public_ip('999.999.999.999'))

if __name__ == '__main__':
    unittest.main() 