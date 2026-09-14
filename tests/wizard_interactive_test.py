"""Exercise the real wizard in a PTY with preview data only. No dependencies."""
import fcntl
import os
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time


def exercise(binary, action):
    master, slave = os.openpty()
    control_read, control_write = os.pipe()
    original = termios.tcgetattr(slave)

    def size(cols, rows):
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    size(80, 24)

    def child():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    proc = subprocess.Popen(
        [sys.executable, __file__, "--hold-terminal", binary, str(control_read)], stdin=slave, stdout=slave, stderr=slave,
        preexec_fn=child, pass_fds=(control_read,), env={**os.environ, "TERM": "xterm-256color"},
    )
    os.close(control_read)
    output = bytearray()

    def read_until(ready, seconds=5):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.02)[0]:
                output.extend(os.read(master, 65536))
                assert len(output) < 2**20, "unbounded terminal output"
            if ready():
                return
        raise AssertionError(f"{action}: terminal did not reach the expected state")

    try:
        read_until(lambda: b"Close preview" in output)
        if action == "resize":
            size(40, 10)
            os.killpg(proc.pid, signal.SIGWINCH)
            read_until(lambda: b"Resize to 48 x 16" in output)
            os.write(master, b"q")
            until = time.monotonic() + 0.15
            read_until(lambda: time.monotonic() >= until)
            assert b"__WIZARD_EXIT__=" not in output, "invisible action was accepted"
            size(80, 24)
            os.killpg(proc.pid, signal.SIGWINCH)
            time.sleep(0.15)
            os.write(master, b"q")
        elif action == "paste":
            os.write(master, b"\x1b[200~q\n\x1b[201~")
            until = time.monotonic() + 0.15
            read_until(lambda: time.monotonic() >= until)
            assert b"__WIZARD_EXIT__=" not in output, "pasted text selected a menu action"
            os.write(master, b"q")
        elif action == "signal":
            os.killpg(proc.pid, signal.SIGTERM)
        else:
            os.write(master, {"quit": b"q", "escape": b"\x1b", "ctrl-c": b"\x03"}[action])
        read_until(lambda: re.search(rb"__WIZARD_EXIT__=(-?\d+)\r?\n", output) is not None)
        assert b"\x1b[?1049l" in output, "alternate screen was left enabled"
        assert termios.tcgetattr(slave) == original, "terminal settings were not restored"
        assert b"\x1b[?2004l" in output, "bracketed paste was left enabled"
        if action in ("quit", "resize", "paste"):
            assert b"__WIZARD_EXIT__=0" in output, "normal preview exit failed"
        os.write(control_write, b"x")
        proc.wait(timeout=5)
        print(f"PASS wizard PTY: {action}")
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
        os.close(master)
        os.close(slave)
        os.close(control_write)


if __name__ == "__main__":
    if sys.argv[1] == "--hold-terminal":
        # Keep the controlling terminal alive after the application exits.
        # macOS revokes its attributes when the session leader exits. These
        # caught handlers reset to defaults when the application is executed.
        signal.signal(signal.SIGINT, lambda *_: None)
        signal.signal(signal.SIGTERM, lambda *_: None)
        status = subprocess.call([sys.argv[2], "preview"])
        print(f"__WIZARD_EXIT__={status}", flush=True)
        os.read(int(sys.argv[3]), 1)
    else:
        for action in ("quit", "escape", "ctrl-c", "signal", "resize", "paste"):
            exercise(os.path.abspath(sys.argv[1]), action)
