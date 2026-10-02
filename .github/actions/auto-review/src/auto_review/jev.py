"""Client for the OpenRouter System One endpoint that answers jev's typed questions."""

import json
import math
import urllib.error
import urllib.request

ENDPOINT = "https://openrouter.ai/api/v1/systemone"
TIMEOUT_SECONDS = 30


class JevError(RuntimeError):
    pass


def ask(
    api_key: str,
    model: str,
    state: object,
    question: str,
    instructions: str,
) -> tuple[float | None, str]:
    """Answer one noul (yes/no) question about ``state``.

    Returns the probability of yes and the model that answered. The probability is None when the
    response carries no answer, which callers treat the same as a low score.
    """
    payload = {
        "model": model,
        "state": state,
        "questions": {question: {"type": "noul", "instructions": instructions}},
    }
    request = urllib.request.Request(
        ENDPOINT,
        method="POST",
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            body = json.load(response)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise JevError(f"systemone request failed: {error}") from error

    answer = body.get("answers", {}).get(question, {})
    model = body.get("model", "unknown")
    probability = answer.get("noul")
    # bool is an int subclass, so a JSON true would otherwise pass as 1.0.
    if isinstance(probability, bool) or not isinstance(probability, (int, float)):
        return None, model
    probability = float(probability)
    # json.loads accepts NaN and Infinity, and NaN compares false against every threshold.
    if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
        return None, model
    return probability, model
