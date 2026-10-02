"""Enable ``python -m loglens`` as an alias for the ``loglens`` console script."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
