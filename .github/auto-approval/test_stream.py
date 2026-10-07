import json
from pathlib import Path
import select
import subprocess
import unittest


FILTER = Path(__file__).with_name("stream.jq")
COMMAND = ["jq", "--unbuffered", "--join-output", "-f", str(FILTER)]


class StreamTests(unittest.TestCase):
    def test_text_and_tool_progress_without_raw_payloads(self):
        events = [
            {"type": "message_update", "assistantMessageEvent": {"type": "text_delta", "delta": "Checking "}},
            {"type": "message_update", "assistantMessageEvent": {"type": "text_delta", "delta": "reviews.\n"}},
            {"type": "message_update", "assistantMessageEvent": {"type": "thinking_delta", "delta": "internal"}},
            {"type": "tool_execution_start", "toolName": "bash", "args": {"command": "private"}},
            {"type": "tool_execution_end", "toolName": "bash", "isError": False, "result": "private"},
            {"type": "message_end", "message": {"role": "assistant", "stopReason": "stop"}},
        ]
        result = subprocess.run(COMMAND, input="".join(json.dumps(e) + "\n" for e in events),
                                text=True, capture_output=True, check=True, timeout=5)
        self.assertEqual(result.stdout, "Checking reviews.\n\n[tool started: bash]\n"
                         "\n[tool finished: bash; error=false]\n\n[assistant finished: stop]\n")

    def test_output_arrives_before_stream_closes(self):
        process = subprocess.Popen(COMMAND, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        try:
            event = {"type": "message_update", "assistantMessageEvent": {
                "type": "text_delta", "delta": "Reviewing now.\n"}}
            process.stdin.write((json.dumps(event) + "\n").encode())
            process.stdin.flush()
            ready, _, _ = select.select([process.stdout], [], [], 5)
            self.assertTrue(ready, "Output was buffered until process exit")
            self.assertEqual(process.stdout.readline(), b"Reviewing now.\n")
        finally:
            process.communicate(timeout=5)
        self.assertEqual(process.returncode, 0)

    def test_malformed_event_fails_the_filter(self):
        result = subprocess.run(COMMAND, input="not json\n", text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
