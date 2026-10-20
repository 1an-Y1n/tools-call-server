#!/usr/bin/env python3
"""Generate a PBKDF2 password hash for the users table (paste into INSERT).

Usage:
  python3 hash_password.py             # prompts for the password (hidden, asked twice)
  python3 hash_password.py <password>  # hash the given argument (visible in shell history)
"""
import getpass
import sys

from server import hash_password


def main():
    if len(sys.argv) > 1:
        pw = sys.argv[1]
    else:
        pw = getpass.getpass("密码: ")
        if pw != getpass.getpass("确认密码: "):
            sys.exit("两次输入不一致")
    if not pw:
        sys.exit("密码不能为空")
    if len(pw) < 8:
        print("警告：密码少于 8 位，网页端创建的用户要求至少 8 位", file=sys.stderr)
    print(hash_password(pw))


if __name__ == "__main__":
    main()
