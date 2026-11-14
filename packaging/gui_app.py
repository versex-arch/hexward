"""Entry point for the packaged desktop application (PyInstaller, windowed)."""
import sys

from hexward.gui import main

if __name__ == "__main__":
    sys.exit(main(background="--background" in sys.argv[1:]))
