#!/bin/bash
# build-launcher-app.sh — compile the launcher AppleScript into a .app
# bundle. Run once after `bin/recce-gui-launch.sh` and `/Applications/Recce.app`
# (the Pake-wrapped UI) are in place.
#
# Output: ~/Applications/Recce.app  (or /Applications if writable)
#
# The launcher .app, when double-clicked, runs the bundled launch script
# which: (1) ensures the Streamlit server is running, (2) opens the
# Pake-wrapped Recce UI window. Drag it to the Dock for one-click access.

set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAUNCH_SH="${REPO_ROOT}/bin/recce-gui-launch.sh"
PAKE_APP="/Applications/Recce.app"
LAUNCHER_NAME="Recce"

if [ ! -x "${LAUNCH_SH}" ]; then
    echo "error: ${LAUNCH_SH} not found or not executable"
    exit 1
fi

# Where to install the launcher. Prefer ~/Applications so we don't
# clobber the Pake-wrapped Recce.app at /Applications/Recce.app.
USER_APPS="${HOME}/Applications"
mkdir -p "${USER_APPS}"
LAUNCHER_PATH="${USER_APPS}/${LAUNCHER_NAME} GUI.app"

# Build a tiny AppleScript that calls the shell launcher.
SCRIPT_TMP="$(mktemp).applescript"
cat > "${SCRIPT_TMP}" <<APPLESCRIPT
on run
    do shell script "${LAUNCH_SH}"
end run
APPLESCRIPT

rm -rf "${LAUNCHER_PATH}"
osacompile -o "${LAUNCHER_PATH}" "${SCRIPT_TMP}"
rm -f "${SCRIPT_TMP}"

echo "✓ Launcher built: ${LAUNCHER_PATH}"
echo
echo "Drag '${LAUNCHER_PATH}' to your Dock. One double-click starts the"
echo "server (if not already running) and opens the Recce window."
echo
if [ ! -d "${PAKE_APP}" ]; then
    echo "⚠️  Note: ${PAKE_APP} is missing. Build & install the Pake-wrapped"
    echo "   UI app first (see README → 'GUI app' section)."
fi
