"""Позволяет запускать `python -m topoguard ...`."""

from .cli import main

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
