#!/usr/bin/env bash
# record-demo.sh — records a hotspot-bpf demo as an animated GIF.
#
# Usage:
#   sudo ./static/record-demo.sh
#
# Requirements:
#   - asciinema (apt install asciinema)
#   - docker with ghcr.io/asciinema/agg (pulled automatically)
#
# Output:
#   static/demo.gif  (animated GIF for README)
#   static/demo.cast (raw asciinema recording, can be replayed with `asciinema play`)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CAST_FILE="$SCRIPT_DIR/demo.cast"
GIF_FILE="$SCRIPT_DIR/demo.gif"
HOTSPOT="$ROOT_DIR/hotspot"

# Sanity checks
if [[ $EUID -ne 0 ]]; then
    echo "Error: must run as root (sudo $0)" >&2
    exit 1
fi

if ! command -v asciinema &>/dev/null; then
    echo "Error: asciinema not found. Install with: apt install asciinema" >&2
    exit 1
fi

if [[ ! -x "$HOTSPOT" ]]; then
    echo "Error: $HOTSPOT not found. Build with: go build -o hotspot ./cmd/hotspot" >&2
    exit 1
fi

# Terminal dimensions for the recording.
# The banner is ~77 chars wide; tables with all columns need ~130.
# Vertically: banner (9) + status (2) + focus (~8) + CPU table (~8) +
# contention (~8) + faults (~8) + padding = ~50 lines minimum.
COLS=140
ROWS=56

echo "=== hotspot-bpf demo recorder ==="
echo "Output: $GIF_FILE"
echo "Terminal: ${COLS}x${ROWS}"
echo ""

# Clean up on exit
cleanup() {
    echo ""
    echo "Cleaning up..."
    # Kill any background processes we started
    [[ -n "${HOTSPOT_PID:-}" ]] && kill "$HOTSPOT_PID" 2>/dev/null || true
    [[ -n "${LEAK_PID:-}" ]] && kill "$LEAK_PID" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

# The inner script that asciinema will record.
# It starts hotspot, triggers a memory leak, waits for detection, then exits.
INNER_SCRIPT=$(cat << 'INNER'
#!/usr/bin/env bash
set -euo pipefail

HOTSPOT_BIN="$1"
TERM_COLS="$2"
TERM_ROWS="$3"

# Propagate terminal dimensions so term.GetSize() works inside the PTY.
stty cols "$TERM_COLS" rows "$TERM_ROWS" 2>/dev/null || true

# Start hotspot with a 3s interval for faster demo
$HOTSPOT_BIN -interval 3s -topk 5 -hide-kernel &
HOTSPOT_PID=$!

# Let hotspot render 2 clean frames (shows the TUI with OK processes)
sleep 7

# Start the memory leak in the background
python3 -c "
import time
x = []
while True:
    x.append(' ' * 10_000_000)
    time.sleep(0.25)
" &
LEAK_PID=$!

# Wait for OOM detection (RSS needs to grow + 2-3 ticks of trend data)
sleep 18

# Kill the leak and let hotspot show one more clean frame
kill $LEAK_PID 2>/dev/null || true
sleep 4

# Done — kill hotspot
kill $HOTSPOT_PID 2>/dev/null || true
wait 2>/dev/null || true
INNER
)

# Write the inner script to a temp file
INNER_FILE=$(mktemp /tmp/hotspot-demo-XXXXX.sh)
echo "$INNER_SCRIPT" > "$INNER_FILE"
chmod +x "$INNER_FILE"

# Record with asciinema
echo "Recording... (this takes ~30 seconds)"
ASCIINEMA_REC_COLS=$COLS ASCIINEMA_REC_ROWS=$ROWS \
    asciinema rec \
    --cols "$COLS" \
    --rows "$ROWS" \
    --overwrite \
    --command "bash $INNER_FILE $HOTSPOT $COLS $ROWS" \
    "$CAST_FILE"

rm -f "$INNER_FILE"

echo ""
echo "Recording saved to $CAST_FILE"

# Convert to GIF using agg (Docker)
if command -v docker &>/dev/null; then
    echo "Converting to GIF with agg..."
    docker run --rm \
        -v "$SCRIPT_DIR:/data" \
        ghcr.io/asciinema/agg \
        --font-size 12 \
        --speed 1.5 \
        --theme monokai \
        /data/demo.cast \
        /data/demo.gif

    echo ""
    echo "Done! GIF saved to $GIF_FILE"
    echo "File size: $(du -h "$GIF_FILE" | cut -f1)"
else
    echo ""
    echo "Docker not found — skipping GIF conversion."
    echo "Convert manually with:"
    echo "  docker run --rm -v $SCRIPT_DIR:/data ghcr.io/asciinema/agg /data/demo.cast /data/demo.gif"
fi
