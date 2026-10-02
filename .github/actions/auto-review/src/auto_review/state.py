"""The files the stages hand to each other, and the workflow output and annotations."""

import json
import os
from pathlib import Path


def directory() -> Path:
    path = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "auto-review"
    path.mkdir(parents=True, exist_ok=True)
    return path


def path(name: str) -> Path:
    return directory() / name


def write_text(name: str, text: str) -> None:
    path(name).write_text(text)


def read_text(name: str) -> str:
    file = path(name)
    return file.read_text() if file.is_file() else ""


def write_json(name: str, value: dict) -> None:
    path(name).write_text(json.dumps(value))


def read_json(name: str) -> dict | None:
    file = path(name)
    if not file.is_file():
        return None
    try:
        return json.loads(file.read_text())
    except json.JSONDecodeError:
        return None


def remove(name: str) -> None:
    path(name).unlink(missing_ok=True)


def set_output(name: str, value: str) -> None:
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write(f"{name}={value}\n")


def notice(message: str) -> None:
    print(f"::notice::{message}", flush=True)


def error(message: str) -> None:
    print(f"::error::{message}", flush=True)
