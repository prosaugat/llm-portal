"""LLM Portal — entry points.

Usage:
    python3 -m llm_portal          # start the web portal
    python3 -m llm_portal proxy    # start the logging reverse proxy
    python3 -m llm_portal.app createsuperuser <name>  # bootstrap admin
"""
import sys


def main():
    if len(sys.argv) < 2:
        # Default: start the web portal
        from .app import main as portal_main
        portal_main()
        return

    cmd = sys.argv[1]
    if cmd == "proxy":
        from .proxy import main as proxy_main
        proxy_main()
    elif cmd in ("createsuperuser", "create-superuser"):
        from .app import createsuperuser
        if len(sys.argv) < 4:
            print("usage: python3 -m llm_portal createsuperuser <username> [password]", file=sys.stderr)
            sys.exit(1)
        name = sys.argv[2]
        pw = sys.argv[3] if len(sys.argv) > 3 else None
        sys.exit(createsuperuser(name, pw))
    elif cmd in ("--version", "-V"):
        from . import __version__
        print(f"llm-portal {__version__}")
    elif cmd in ("--help", "-h"):
        print(__doc__)
    else:
        print(f"unknown command: {cmd}", file=sys.stderr)
        print(__doc__, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
