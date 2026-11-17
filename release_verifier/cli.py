"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sys
from pathlib import Path

from . import __version__, alerts, verify, watch
from .config import ConfigError, load
from .results import EXIT_OK, EXIT_TOOL_ERROR, Report
from .state import State

log = logging.getLogger("release_verifier")


def _csv(values: list[str] | None) -> list[str] | None:
    if not values:
        return None
    return [x for v in values for x in v.split(",") if x]


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="release-verifier",
        description="Independently verify published releases and watch their mutable state.",
        epilog="Exit codes: 0 = no compromise-class findings, 1 = compromise-class finding, 2 = tool/infra error.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging and list passing checks")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--project", required=True, help="project name (projects/<name>.json) or path to a config file")
        sp.add_argument("--state", type=Path, default=os.environ.get("RELEASE_VERIFIER_STATE"),
                        help="state directory (default: $RELEASE_VERIFIER_STATE)")
        sp.add_argument("--json", metavar="PATH", help="also write the JSON report to PATH ('-' = stdout, summary goes to stderr)")
        sp.add_argument("--no-alerts", action="store_true", help="do not send alerts even if sinks are configured")

    w = sub.add_parser("watch", help="snapshot mutable release state and diff it against the previous snapshot")
    common(w)
    w.add_argument("--accept", action="store_true", help="advance the baseline even if the diff has compromise-class findings")

    v = sub.add_parser("verify", help="fully verify one release tag")
    common(v)
    v.add_argument("--tag", required=True)
    v.add_argument("--work-dir", type=Path, help="scratch space for downloads/rebuilds (default: <state>/work)")
    v.add_argument("--skip-rebuild", action="store_true", help="skip package and image rebuilds")
    v.add_argument("--skip-image-rebuild", action="store_true", help="rebuild packages but not images")
    v.add_argument("--platforms", nargs="+", help="package platforms to compare against the rebuild (default: all)")
    v.add_argument("--image-platforms", nargs="+", help="image platforms to rebuild, e.g. linux/amd64 (default: all)")
    v.add_argument("--flavors", nargs="+", help="image flavors to check (default: all)")
    v.add_argument("--builder", default="release-verifier", help="docker-container buildx builder (created if missing)")
    v.add_argument("--no-cache", action="store_true", help="do not reuse local Docker build caches (packages and images)")
    v.add_argument("--keep-work", action="store_true", help="keep downloads, checkout and rebuild output")

    c = sub.add_parser("check-config", help="validate a project config and print a summary")
    c.add_argument("--project", required=True)
    return p


def _emit(report: Report, args: argparse.Namespace, state: State) -> int:
    data = report.to_json()
    path = state.save_report(data)
    summary = report.summary(verbose=args.verbose) + f"\n   report: {path}"
    if args.json == "-":
        print(summary, file=sys.stderr)
        print(json.dumps(data, indent=2))
    else:
        print(summary)
        if args.json:
            Path(args.json).write_text(json.dumps(data, indent=2))
    code = report.exit_code
    if not args.no_alerts and not alerts.dispatch(report, state.dir) and code == EXIT_OK:
        code = EXIT_TOOL_ERROR
    return code


def _missing_tools(tools: list[str]) -> list[str]:
    return [t for t in tools if shutil.which(t) is None]


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    try:
        project = load(args.project)
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return EXIT_TOOL_ERROR

    if args.command == "check-config":
        print(json.dumps({
            "project": project.name,
            "repo": project.repo,
            "platforms": [p.name for p in project.platforms],
            "flavors": [f["name"] for f in project.flavors],
            "channels": [c.get("name", c["type"]) for c in project.channels],
            "fingerprint": project.fingerprint,
        }, indent=2))
        return EXIT_OK

    if not args.state:
        print("--state (or RELEASE_VERIFIER_STATE) is required", file=sys.stderr)
        return EXIT_TOOL_ERROR
    needed = ["git", "gpg"] + (["docker"] if args.command == "verify" and not args.skip_rebuild else [])
    if missing := _missing_tools(needed):
        print(f"missing required tools: {', '.join(missing)}", file=sys.stderr)
        return EXIT_TOOL_ERROR
    state = State(args.state.resolve(), project.name)

    try:
        if args.command == "watch":
            report = watch.run(project, state, accept=args.accept)
        else:
            unknown = set(_csv(args.platforms) or []) - {p.name for p in project.platforms}
            if unknown:
                print(f"unknown platforms: {', '.join(sorted(unknown))}", file=sys.stderr)
                return EXIT_TOOL_ERROR
            opts = verify.Options(
                tag=args.tag,
                work_dir=(args.work_dir or args.state / "work").resolve(),
                skip_rebuild=args.skip_rebuild,
                skip_image_rebuild=args.skip_image_rebuild,
                platforms=_csv(args.platforms),
                image_platforms=_csv(args.image_platforms),
                flavors=_csv(args.flavors),
                builder=args.builder,
                no_cache=args.no_cache,
                keep_work=args.keep_work,
            )
            report = verify.run(project, state, opts)
    except KeyboardInterrupt:
        return EXIT_TOOL_ERROR
    except Exception as e:  # noqa: BLE001 - last-resort: never exit 0/1 on a crash
        log.exception("unexpected failure")
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        return EXIT_TOOL_ERROR
    return _emit(report, args, state)


if __name__ == "__main__":
    sys.exit(main())
