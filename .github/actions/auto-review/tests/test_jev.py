import json
import unittest
import urllib.error
from unittest import mock

from auto_review import jev


class FakeResponse:
    def __init__(self, payload: dict):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *arguments):
        return False

    def read(self):
        return json.dumps(self.payload).encode()


def answer(noul, model="typesafe/jev-1.13-20260917") -> FakeResponse:
    return FakeResponse({"model": model, "answers": {"approve": {"type": "noul", "noul": noul}}})


class AskTest(unittest.TestCase):
    def ask(self, noul):
        with mock.patch.object(jev.urllib.request, "urlopen", return_value=answer(noul)):
            return jev.ask("key", "typesafe/jev-1.13", {}, "approve", "instructions")

    def test_returns_the_probability_and_model(self):
        score, model = self.ask(0.96)
        self.assertEqual(score, 0.96)
        self.assertEqual(model, "typesafe/jev-1.13-20260917")

    def test_missing_answer_is_none(self):
        response = FakeResponse({"model": "m", "answers": {}})
        with mock.patch.object(jev.urllib.request, "urlopen", return_value=response):
            score, _ = jev.ask("key", "m", {}, "approve", "instructions")
        self.assertIsNone(score)

    def test_non_probabilities_are_none(self):
        # json.loads accepts NaN and Infinity, and NaN compares false against every threshold.
        for value in [float("nan"), float("inf"), -0.1, 1.1, True, "0.9", None]:
            score, _ = self.ask(value)
            self.assertIsNone(score, f"{value!r} was accepted as a probability")

    def test_transport_failure_raises(self):
        with mock.patch.object(
            jev.urllib.request, "urlopen", side_effect=urllib.error.URLError("no route")
        ):
            with self.assertRaises(jev.JevError):
                jev.ask("key", "m", {}, "approve", "instructions")


if __name__ == "__main__":
    unittest.main()
