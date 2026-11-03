"""Общие фикстуры тестов команды Б3.

Встроенный плагин ``tmpdir`` отключён в ``pyproject.toml``: он создаёт
каталоги с режимом ``0o700``, что несовместимо с политикой файловой
песочницы стенда. Вместо него используется фикстура ``workdir``.
"""

from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

import pytest

BUILD_ROOT = Path(__file__).resolve().parent.parent / "build" / "test-tmp"


@pytest.fixture()
def workdir() -> Path:
    """Изолированный каталог для файловых артефактов теста."""
    BUILD_ROOT.mkdir(parents=True, exist_ok=True)
    path = BUILD_ROOT / uuid.uuid4().hex[:12]
    # Без явного mode: каталог должен наследовать DACL рабочей области.
    os.makedirs(path)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)
