#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import time
from pathlib import Path


def expired_archives(root: Path, now: int):
    resolved_root = root.resolve()
    for marker in resolved_root.rglob(".retention.json"):
        if marker.is_symlink():
            continue
        archive = marker.parent.resolve()
        try:
            archive.relative_to(resolved_root)
            metadata = json.loads(marker.read_text(encoding="utf-8"))
            archived_at = int(metadata["archived_at"])
            retention_days = int(metadata["retention_days"])
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            continue
        if not 1 <= retention_days <= 3650:
            continue
        if archived_at + retention_days * 86400 <= now:
            yield archive


def main():
    parser = argparse.ArgumentParser(description="JCode 보관 기한이 지난 디렉터리를 정리합니다.")
    parser.add_argument("--root", default=os.getenv("WORKSPACE_ARCHIVE_ROOT", "/archive-data"))
    parser.add_argument("--apply", action="store_true", help="생략하면 삭제 대상을 출력만 합니다.")
    args = parser.parse_args()
    root = Path(args.root)
    if not root.is_absolute() or not root.is_dir():
        raise SystemExit(f"유효한 archive root가 필요합니다: {root}")
    targets = list(expired_archives(root, int(time.time())))
    for target in targets:
        print(target)
        if args.apply:
            shutil.rmtree(target)
    print(json.dumps({"expired": len(targets), "applied": args.apply}))


if __name__ == "__main__":
    main()
