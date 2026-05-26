"""Console-script entry point: starts the Streamlit server.

Equivalent to running::

    streamlit run <path-to-recce>/recce/gui/app.py --server.port 8501

…but resolves the bundled ``app.py`` via ``importlib.resources`` so it
works regardless of how recce is installed (pipx, editable, wheel).
"""

from __future__ import annotations

import sys
from importlib import resources
from pathlib import Path


def main() -> None:
    try:
        from streamlit.web.cli import main as st_main
    except ModuleNotFoundError:
        sys.stderr.write(
            "recce-gui needs Streamlit. Reinstall with the [gui] extra:\n"
            "    pipx install '/path/to/recce[gui]' --force\n"
            "or:\n"
            "    pipx inject recce streamlit pandas\n"
        )
        sys.exit(1)

    app_path = Path(str(resources.files("recce.gui").joinpath("app.py")))
    # Hand off argv to streamlit's CLI.
    args = [
        "streamlit", "run", str(app_path),
        "--server.port", "8501",
        "--server.headless", "true",
        "--browser.gatherUsageStats", "false",
        "--server.runOnSave", "false",
        *sys.argv[1:],
    ]
    sys.argv = args
    st_main()


if __name__ == "__main__":
    main()
