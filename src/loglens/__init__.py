"""LogLens defensive log analysis toolkit."""

from .syslog import parse_rfc5424_line

__version__ = "0.4.0"

__all__ = ["parse_rfc5424_line", "__version__"]
