# Offline demo fixtures

These files are intentionally small static scanner inputs. Do not execute their cryptographic examples or use them as production configuration.

- `workspace/`: Python cryptography signals, a legacy nginx configuration and a dependency manifest copied from seed_corpus.
- `image-inventory.json`: synthetic CycloneDX package inventory demonstrating offline image ingestion. It is not a measured live image result.
- For an empty-result demo, create an empty directory and scan its absolute path.

The documentation delivery includes a ZIP of workspace/ for the upload demo. You can regenerate it with Python's zipfile module.
