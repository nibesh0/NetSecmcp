import unittest

from src.netsecmcp.core.permissions import AuthorizationEngine
from src.netsecmcp.core.validator import validate_network_target, validate_port_range


class AuthorizationTests(unittest.TestCase):
    def test_private_lab_network_is_allowed(self):
        engine = AuthorizationEngine()
        decision = engine.authorize("192.168.1.10")
        self.assertTrue(decision.authorized)

    def test_public_range_is_denied(self):
        engine = AuthorizationEngine()
        decision = engine.authorize("8.8.8.8")
        self.assertFalse(decision.authorized)

    def test_network_validation_rejects_large_ranges(self):
        with self.assertRaises(Exception):
            validate_network_target("10.0.0.0/8")

    def test_port_range_validation(self):
        ports = validate_port_range("22,80-81")
        self.assertEqual(ports, [22, 80, 81])


if __name__ == "__main__":
    unittest.main()
