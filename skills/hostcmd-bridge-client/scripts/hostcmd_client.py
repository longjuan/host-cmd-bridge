#!/usr/bin/env python3
import argparse
import json
import os
import socket
import sys
import time
import uuid
from typing import Any, Dict, List


def gen_request_id() -> str:
    ts = int(time.time())
    return f"req-{ts}-{uuid.uuid4().hex[:12]}"


def default_socket_path() -> str:
    env = os.getenv("HOSTCMD_SOCKET")
    if env:
        return env
    script_dir = os.path.dirname(os.path.abspath(__file__))
    skill_dir = os.path.dirname(script_dir)
    return os.path.join(skill_dir, "hostcmd.sock")


def send_jsonl(socket_path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    data = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        try:
            sock.connect(socket_path)
        except PermissionError as err:
            raise PermissionError(f"connect unix socket permission denied: {socket_path}") from err
        except FileNotFoundError as err:
            raise FileNotFoundError(f"unix socket not found: {socket_path}") from err
        sock.sendall(data)

        buf = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            if b"\n" in buf:
                line, _ = buf.split(b"\n", 1)
                if not line:
                    raise RuntimeError("empty response line")
                return json.loads(line.decode("utf-8"))

    raise RuntimeError("connection closed before newline response")


def build_submit_payload(args: argparse.Namespace) -> Dict[str, Any]:
    request_id = args.request_id
    if request_id == "auto":
        request_id = gen_request_id()

    return {
        "action": "submit",
        "request_id": request_id,
        "command": args.command,
        "args": args.arg or [],
        "reason": args.reason,
        "timeout_sec": args.timeout_sec,
    }


def build_query_payload(args: argparse.Namespace) -> Dict[str, Any]:
    return {
        "action": "query",
        "request_id": args.request_id,
    }


def normalize_argv(argv: List[str]) -> List[str]:
    out: List[str] = []
    i = 0
    known_submit_opts = {
        "--socket",
        "--request-id",
        "--command",
        "--arg",
        "--reason",
        "--timeout-sec",
    }
    while i < len(argv):
        cur = argv[i]
        if cur == "--arg" and i + 1 < len(argv):
            nxt = argv[i + 1]
            # Allow values like "-al" for --arg by rewriting as --arg=-al.
            if nxt.startswith("-") and nxt not in known_submit_opts:
                out.append(f"--arg={nxt}")
                i += 2
                continue
        out.append(cur)
        i += 1
    return out


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="host-cmd-bridge Unix socket client")
    parser.add_argument("--socket", default=default_socket_path(), help="Unix socket path")

    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_submit = sub.add_parser("submit", help="submit command execution request")
    p_submit.add_argument("--request-id", default="auto", help='request id, default "auto"')
    p_submit.add_argument("--command", required=True, help="command executable")
    p_submit.add_argument("--arg", action="append", default=[], help="argument (repeatable)")
    p_submit.add_argument("--reason", required=True, help="execution reason")
    p_submit.add_argument("--timeout-sec", type=int, default=30, help="command timeout seconds")

    p_query = sub.add_parser("query", help="query request status/result")
    p_query.add_argument("--request-id", required=True, help="request id")

    return parser.parse_args(normalize_argv(argv))


def main() -> int:
    args = parse_args(sys.argv[1:])

    if args.subcommand == "submit":
        payload = build_submit_payload(args)
    elif args.subcommand == "query":
        payload = build_query_payload(args)
    else:
        raise RuntimeError(f"unsupported subcommand: {args.subcommand}")

    resp = send_jsonl(args.socket, payload)
    print(json.dumps(resp, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
