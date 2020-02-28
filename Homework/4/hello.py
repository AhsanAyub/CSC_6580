#!/usr/bin/env python3
#

import sys

def hello(name):
    print(f"Hello {name}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Missing Name")
    else:
        for name in sys.argv[1:]:
            hello(name)
