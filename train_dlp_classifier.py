"""CLI entry point; implementation lives in the single dlp application."""
from dlp.management.commands.train_dlp_classifier import main

if __name__ == '__main__':
    main()
