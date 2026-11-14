"""Entry point for the packaged command-line tool (PyInstaller, console)."""
import sys

from hexward.cli import main

if __name__ == "__main__":
    sys.exit(main())
