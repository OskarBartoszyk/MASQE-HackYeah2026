import importlib.util
import io
import pathlib
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("corporate_agent", pathlib.Path(__file__).with_name("agent.py"))
agent = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agent)


class AutonomousAgentTests(unittest.TestCase):
    def test_local_agent_plans_acts_and_answers_through_gateway(self):
        calls = []

        def guarded_call(*args):
            calls.append(args)
            action = args[5]
            if len(calls) == 1:
                return {"evaluation": {"decision": "ALLOW"}, "executed": True,
                        "result": '{"action":"reports.read","resource":"reports/Q4.pdf"}'}
            if action == "reports.read":
                return {"evaluation": {"decision": "ALLOW"}, "executed": True,
                        "result": "Q4 revenue increased by 12%."}
            return {"evaluation": {"decision": "ALLOW"}, "executed": True,
                    "result": "Revenue rose 12%."}

        with patch.object(agent, "execute", side_effect=guarded_call), redirect_stdout(io.StringIO()):
            agent.autonomous("http://localhost:8080", "demo-key", "session-1", "gemma3:4b", "Summarize Q4")
        self.assertEqual([call[5] for call in calls], ["llm.generate", "reports.read", "llm.generate"])
        self.assertTrue(all(call[0] == "http://localhost:8080" for call in calls))

    def test_blocked_planner_never_calls_tool(self):
        calls = []

        def blocked(*args):
            calls.append(args)
            return {"evaluation": {"decision": "BLOCK"}, "executed": False}

        with patch.object(agent, "execute", side_effect=blocked), redirect_stdout(io.StringIO()):
            agent.autonomous("http://localhost:8080", "demo-key", "session-2", "gemma3:4b", "unsafe request")
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
