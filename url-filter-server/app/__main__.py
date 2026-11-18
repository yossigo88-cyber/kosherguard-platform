"""Deployment entrypoint for the URL Filter dataset service:
`python -m app` (config via environment, matching the other
KosherGuard services' env-file convention). STATUS: configuration
wiring only - never installed or started by the code build.

Environment:
  KG_PUBLICATION_ROOT   tenant publication root to watch (the
                        control-plane Publisher's per-tenant tree).
                        Required: the dataset always derives from a
                        published generation, never a fixture.
  KG_DEVICE_TOKEN_KEY   per-device credential verification key.
  KG_WATCH_INTERVAL     publication poll seconds (default 60).
  KG_LISTEN             host:port (default 127.0.0.1:9000).
  KG_PIR_EXPORT_PATH    when set, every successful dataset swap also
                        writes the DEVICE PIR export
                        (pir_export.export_device_textpb, block-only
                        presence rows with the provenance marker) to
                        this path, atomically (tmp + rename).
  KG_PIR_REGEN_CMD      when set, run after the export is written
                        (e.g. prepare-dataset + SIGHUP the PIR
                        service). Staged activation: the export and
                        this command complete BEFORE the new dataset
                        is served; a failure keeps the last good
                        generation serving and the poll retries, so
                        Bloom/prefilter and the PIR data never serve
                        different committed generations.

The automatic chain: control-plane publish (publication worker ->
Publisher activates the generation) -> PublicationWatcher poll ->
build_dataset -> device PIR export + regeneration (staged) ->
DatasetRef swap -> served manifest/prefilter/shards change. No human
POST and no restart anywhere in the chain.
"""

import os
import subprocess

from .dataset import build_dataset
from .publication_watch import PublicationWatcher, rules_from_generation
from .server import DatasetRef, create_app


def main() -> None:
    root = os.environ.get("KG_PUBLICATION_ROOT", "").strip()
    if not root:
        raise SystemExit("KG_PUBLICATION_ROOT is required")
    export_path = os.environ.get("KG_PIR_EXPORT_PATH", "").strip() \
        or None
    regen_cmd = os.environ.get("KG_PIR_REGEN_CMD", "").strip() or None
    interval = float(os.environ.get("KG_WATCH_INTERVAL", "60"))
    listen = os.environ.get("KG_LISTEN", "127.0.0.1:9000")
    host, _, port = listen.rpartition(":")

    def export_and_regen(dataset) -> None:
        if export_path is None:
            return
        from .pir_export import export_device_textpb
        text = export_device_textpb(dataset.rules)
        tmp = export_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, export_path)
        if regen_cmd is not None:
            subprocess.run(regen_cmd, shell=True, check=True,
                           timeout=600)

    # Initial dataset: built from the CURRENT generation, or the
    # service refuses to start (an empty/seed dataset would serve a
    # policy nobody published).
    initial_dir = PublicationWatcher.current_dir_static(root)
    if initial_dir is None:
        raise SystemExit(
            f"no published generation under {root}; refusing to serve "
            "an empty dataset")
    rules = rules_from_generation(initial_dir)
    import json as _json
    generation = int(_json.loads(
        (initial_dir / "manifest.json").read_bytes()
        .decode("utf-8"))["generation"])
    dataset = build_dataset(rules, version=generation,
                            provenance=f"publication:{root}")
    ref = DatasetRef(dataset)
    watcher = PublicationWatcher(root, ref, on_swap=export_and_regen)
    watcher.start_refresh_loop(interval=interval)
    app = create_app(dataset, dataset_ref=ref)

    import uvicorn
    uvicorn.run(app, host=host or "127.0.0.1", port=int(port or 9000))


if __name__ == "__main__":
    main()
