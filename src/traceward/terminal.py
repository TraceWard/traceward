"""OCI console FD transfer and terminal forwarding (Linux supervisor only)."""
import array
import fcntl
import os
import select
import signal
import socket
import termios
import threading
import tty


class ConsoleProxy:
    def __init__(self, server):
        with server.accept()[0] as conn:
            _, anc, _, _ = conn.recvmsg(1, socket.CMSG_SPACE(4))
        descriptors = array.array("i")
        for level, kind, data in anc:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                descriptors.frombytes(data[:4])
        if len(descriptors) != 1:
            raise RuntimeError("gVisor did not provide an OCI console")
        self.fd = descriptors[0]
        self.old = termios.tcgetattr(0)
        self.stop = threading.Event()
        self.previous = signal.signal(signal.SIGWINCH, self.resize)
        self.resize()
        tty.setraw(0)
        self.thread = threading.Thread(target=self.pump, daemon=True)

    def resize(self, *_):
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, fcntl.ioctl(0, termios.TIOCGWINSZ, b"\0" * 8))

    def start(self):
        self.thread.start()

    def pump(self):
        while not self.stop.is_set():
            try:
                ready, _, _ = select.select([0, self.fd], [], [], 0.1)
                for fd in ready:
                    data = os.read(fd, 65536)
                    if not data:
                        return
                    destination = self.fd if fd == 0 else 1
                    remaining = memoryview(data)
                    while remaining:
                        written = os.write(destination, remaining)
                        remaining = remaining[written:]
            except OSError:
                return

    def close(self):
        self.stop.set()
        self.thread.join(1)
        signal.signal(signal.SIGWINCH, self.previous)
        termios.tcsetattr(0, termios.TCSADRAIN, self.old)
        os.close(self.fd)
