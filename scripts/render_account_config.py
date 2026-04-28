#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path
import yaml

from account_config import load_account_config


def main() -> int:
    if len(sys.argv) != 2:
        print('usage: render_account_config.py <account_dir>', file=sys.stderr)
        return 1
    data = load_account_config(Path(sys.argv[1]))
    print(yaml.safe_dump(data, sort_keys=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
