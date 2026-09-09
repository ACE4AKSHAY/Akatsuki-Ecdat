# Offline demo fixtures

These files are intentionally small static scanner inputs. Do not execute their cryptographic examples or use them as production configuration.

- `workspace/`: Python cryptography signals, a legacy nginx configuration and a dependency manifest copied from seed_corpus.
- `image-inventory.json`: synthetic CycloneDX package inventory demonstrating offline image ingestion. It is not a measured live image result.
- For an empty-result demo, create an empty directory and scan its absolute path.

Create an upload ZIP on Windows with `Compress-Archive -Path .\workspace\* -DestinationPath .\demo-workspace.zip` from this directory, or use Python's zipfile module.

See [the test data map](../documentation/TEST_DATA.md) for all test inputs and the four certificate fixtures in `seed_corpus/certs/`. Install the repository-root `requirements.txt` for the application; the manifest under `demo/workspace` is only scanner input. The PEM fixtures are not certificates for HTTPS hosting or Windows trust stores.
