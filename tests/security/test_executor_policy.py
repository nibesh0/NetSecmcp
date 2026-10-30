import asyncio
import unittest

from src.netsecmcp.core.executor import AsyncExecutor
from src.netsecmcp.config import NetSecConfig


class ExecutorPolicyTests(unittest.TestCase):
    def test_allowlisted_executable_executes(self):
        async def run_test():
            result = await AsyncExecutor(NetSecConfig()).execute("python", "-c", "print('ok')", timeout=10)
            self.assertEqual(result.returncode, 0)
            self.assertIn("ok", result.stdout)

        asyncio.run(run_test())

    def test_unapproved_executable_is_blocked(self):
        async def run_test():
            with self.assertRaises(Exception):
                await AsyncExecutor(NetSecConfig()).execute("bash", "-lc", "echo nope", timeout=10)

        asyncio.run(run_test())


if __name__ == "__main__":
    unittest.main()
