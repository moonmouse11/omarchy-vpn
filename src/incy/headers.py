"""HTTP headers for INCY subscription fetches."""

from pathlib import Path

INCY_CONFIG = Path.home() / ".config/incy"
INCY_VERSION_FALLBACK = "3.9.0"


def incy_headers() -> dict[str, str]:
    headers = {"User-Agent": f"Incy/{INCY_VERSION_FALLBACK}"}
    path = INCY_CONFIG / "hwid"
    try:
        hwid = path.read_text().strip()
    except OSError:
        hwid = ""
    if hwid:
        headers["X-HWID"] = hwid
    return headers
