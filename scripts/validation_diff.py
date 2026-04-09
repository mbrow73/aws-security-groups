#!/usr/bin/env python3
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

COMMENT_MARKER = "<!-- sg-validation-diff -->"


def run_validate(repo_root: Path, account_dir: Path):
    result = subprocess.run(
        [sys.executable, str(repo_root / 'scripts' / 'validate.py'), str(account_dir), '--format', 'json', '--verbose'],
        capture_output=True,
        text=True,
        cwd=str(repo_root),
    )
    try:
        payload = json.loads(result.stdout or '{}')
    except json.JSONDecodeError:
        payload = {'validation_results': {'errors': [], 'warnings': [], 'info': []}, 'summary': {'exit_code': result.returncode}}
    return result.returncode, payload


def normalize_text(value: str) -> str:
    value = value or ''
    value = re.sub(r'\[\d+\]', '[]', value)
    value = re.sub(r'\s+', ' ', value).strip()
    return value


def fingerprint(finding: dict) -> str:
    rule = finding.get('rule', '')
    level = finding.get('level', '')
    context = normalize_text(finding.get('context', ''))
    message = normalize_text(finding.get('message', ''))
    return f"{level}|{rule}|{context}|{message}"


def bucketize(results: dict):
    out = []
    for level in ('errors', 'warnings', 'info'):
        for item in results.get(level, []) or []:
            item = dict(item)
            item['_bucket'] = level
            item['_fingerprint'] = fingerprint(item)
            out.append(item)
    return out


def render_group(title: str, items: list, icon: str):
    if not items:
        return []
    lines = [f"### {icon} {title}"]
    for item in items:
        msg = item.get('message', '').strip()
        ctx = item.get('context')
        rule = item.get('rule')
        extra = []
        if ctx:
            extra.append(ctx)
        if rule:
            extra.append(rule)
        suffix = f" _({' | '.join(extra)})_" if extra else ''
        lines.append(f"- {msg}{suffix}")
    lines.append("")
    return lines


def main():
    if len(sys.argv) < 2:
        print('usage: validation_diff.py <account_dir> [base_ref]', file=sys.stderr)
        sys.exit(2)

    account_dir = Path(sys.argv[1]).resolve()
    base_ref = sys.argv[2] if len(sys.argv) > 2 else os.environ.get('BASE_REF', 'main')
    repo_root = Path.cwd().resolve()

    rel_account = account_dir.relative_to(repo_root)
    rel_file = rel_account / 'security-groups.yaml'
    base_tmp_root = repo_root / '.validation-base'
    base_account_dir = base_tmp_root / rel_account
    base_account_dir.mkdir(parents=True, exist_ok=True)
    base_file = base_account_dir / 'security-groups.yaml'

    show = subprocess.run(
        ['git', 'show', f'origin/{base_ref}:{rel_file.as_posix()}'],
        capture_output=True,
        text=True,
        cwd=str(repo_root),
    )
    if show.returncode == 0:
        base_file.write_text(show.stdout)
        base_exists = True
    else:
        if base_file.exists():
            base_file.unlink()
        base_exists = False

    _, head_payload = run_validate(repo_root, account_dir)
    head_results = bucketize(head_payload.get('validation_results', {}))

    if base_exists:
        _, base_payload = run_validate(repo_root, base_account_dir)
        base_results = bucketize(base_payload.get('validation_results', {}))
    else:
        base_results = []

    head_map = {item['_fingerprint']: item for item in head_results}
    base_map = {item['_fingerprint']: item for item in base_results}

    new_items = [head_map[k] for k in sorted(head_map.keys() - base_map.keys())]
    existing_items = [head_map[k] for k in sorted(head_map.keys() & base_map.keys())]
    resolved_items = [base_map[k] for k in sorted(base_map.keys() - head_map.keys())]

    lines = [COMMENT_MARKER, '## 🔍 Security Group Validation Diff', '']
    lines.append(f"**Account:** `{account_dir.name}` | **New:** {len(new_items)} | **Pre-existing:** {len(existing_items)} | **Resolved:** {len(resolved_items)}")
    lines.append("")

    def split(items, bucket):
        return [i for i in items if i['_bucket'] == bucket]

    lines += render_group('New blocking findings', split(new_items, 'errors'), '❌')
    lines += render_group('New review findings', split(new_items, 'warnings'), '⚠️')
    lines += render_group('New context items', split(new_items, 'info'), 'ℹ️')

    if existing_items:
        lines.append('<details>')
        lines.append(f"<summary>Pre-existing findings ({len(existing_items)})</summary>")
        lines.append('')
        lines += render_group('Pre-existing blocking', split(existing_items, 'errors'), '❌')
        lines += render_group('Pre-existing review', split(existing_items, 'warnings'), '⚠️')
        lines += render_group('Pre-existing context', split(existing_items, 'info'), 'ℹ️')
        lines.append('</details>')
        lines.append('')

    if resolved_items:
        lines.append('<details>')
        lines.append(f"<summary>Resolved findings ({len(resolved_items)})</summary>")
        lines.append('')
        lines += render_group('Resolved blocking', split(resolved_items, 'errors'), '✅')
        lines += render_group('Resolved review', split(resolved_items, 'warnings'), '✅')
        lines += render_group('Resolved context', split(resolved_items, 'info'), '✅')
        lines.append('</details>')
        lines.append('')

    print('\n'.join(lines).strip())


if __name__ == '__main__':
    main()
