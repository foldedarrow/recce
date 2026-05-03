#!/bin/bash
# recce-gui-launch.sh — start the Streamlit server (if not already up) and
# open the Pake-wrapped Recce.app. Designed to be wrapped as an Automator /
# AppleScript .app for one-click launching from the Dock.
#
# Usage:  ./recce-gui-launch.sh
#         (or invoke from the .app's launcher.applescript)

set -e

PORT=8501
URL="http://localhost:${PORT}/"
RECCE_APP="/Applications/Recce.app"
LOG_DIR="${HOME}/Library/Logs/recce"
LOG_FILE="${LOG_DIR}/gui.log"
mkdir -p "${LOG_DIR}"

# pipx puts recce-gui in ~/.local/bin (which isn't always on launchd's PATH
# when invoked via Finder), so resolve it explicitly.
RECCE_GUI_BIN="${HOME}/.local/bin/recce-gui"
if ! [ -x "${RECCE_GUI_BIN}" ]; then
    RECCE_GUI_BIN="$(command -v recce-gui || true)"
fi
if [ -z "${RECCE_GUI_BIN}" ]; then
    osascript -e 'display alert "recce" message "recce-gui not found.\n\nReinstall with:\n  pipx install '"'"'~/Documents/Claude/Projects/recce[gui]'"'"' --force"'
    exit 1
fi

# Already running?
if curl -s -m 2 -o /dev/null "${URL}"; then
    open "${RECCE_APP}"
    exit 0
fi

# Start the server detached.
nohup "${RECCE_GUI_BIN}" > "${LOG_FILE}" 2>&1 &
SERVER_PID=$!
disown $SERVER_PID 2>/dev/null || true

# Wait up to 20s for the port to come up.
for _ in $(seq 1 40); do
    if curl -s -m 1 -o /dev/null "${URL}"; then
        break
    fi
    sleep 0.5
done

if ! curl -s -m 2 -o /dev/null "${URL}"; then
    osascript -e "display alert \"recce\" message \"Server didn't come up on port ${PORT}.\nCheck the log:\n${LOG_FILE}\""
    exit 1
fi

open "${RECCE_APP}"
