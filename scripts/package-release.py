#!/usr/bin/env python3
"""验证已提交的精简内核和部署包，生成发行资产及校验值。"""

import argparse
import hashlib
from pathlib import Path
import re
import shutil
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="发行资产输出目录")
    parser.add_argument("--tag", help="预期标签，例如 v2026.10.17.2")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source = (root / "_worker.js").read_bytes()
    versions = set(re.findall(rb'[\x22\x27](20\d{2}\.\d{1,2}\.\d{1,2}\.\d+)[\x22\x27]', source))
    if len(versions) != 1:
        raise SystemExit("内核版本标记缺失或不唯一，停止发行。")
    version = versions.pop().decode("ascii")
    if args.tag and args.tag != f"v{version}":
        raise SystemExit(f"标签 {args.tag} 与内核版本 v{version} 不一致。")
    if not (root / "docs" / "releases" / f"{version}.md").is_file():
        raise SystemExit(f"缺少 docs/releases/{version}.md，停止发行。")
    archive = root / "pages.zip"
    with zipfile.ZipFile(archive) as package:
        if package.namelist() != ["_worker.js"]:
            raise SystemExit("pages.zip 根目录必须只有 _worker.js。")
        if package.read("_worker.js") != source:
            raise SystemExit("pages.zip 与 _worker.js 不一致，请先同步部署包。")
    output = args.output.resolve()
    if output == root:
        raise SystemExit("请使用独立的发行输出目录，例如 dist。")
    output.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(root / "_worker.js", output / "_worker.js")
    shutil.copyfile(archive, output / "Pages.zip")
    checksums = []
    for name in ("Pages.zip", "_worker.js"):
        digest = hashlib.sha256((output / name).read_bytes()).hexdigest()
        checksums.append(f"{digest}  {name}\n")
    (output / "SHA256SUMS.txt").write_text("".join(checksums), encoding="utf-8")
    print(f"已验证内核 {version}：{len(source):,} 字节，部署包单文件，内容一致。")
    print(f"发行资产：{output}")


if __name__ == "__main__":
    main()
