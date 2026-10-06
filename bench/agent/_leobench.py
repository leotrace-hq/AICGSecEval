"""Shared LeoBench-arm helpers for the A.S.E agent adapters.

These port the pieces of LeoBench's harness that the `leoprevent` arm needs, adapted from
running agents in a container to running them on the host:

  - load a KEY=VALUE .env file (creds shared with the LeoPrevent server);
  - strip the operator's own LeoPrevent registration from a copied Codex config.toml, so the
    host's globally-installed plugin does not load a SECOND time (the double-review bug);
  - stage a throwaway CODEX_HOME (auth.json + sanitized config.toml) so a token refresh lands
    on the copy and the operator's real ~/.codex is untouched;
  - build a local Codex marketplace around the plugin, for `codex plugin add`.
"""
import json
import os
import shutil


def load_env_file(path):
    """Parse a KEY=VALUE .env file into a dict. Missing file → {} (caller falls back to env)."""
    out = {}
    if not path or not os.path.isfile(path):
        return out
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
    return out


# Every Codex run gets THIS config.toml, never the operator's. Copying ~/.codex/config.toml
# carried the Codex app's default model and effort, MCP servers (a Snyk scanner among them),
# OpenAI plugins (code-review, browser), a notify hook and the operator's own leoprevent
# registration (a second Stop hook) into the benchmark. Only the hooks feature is set, because
# the leoprevent arm's plugin hooks need it; model, effort and web access are flags.
CODEX_RUN_CONFIG = """# Written by the LeoBench arm for one run; the operator's ~/.codex/config.toml is never copied.
[features]
hooks = true
"""


def stage_codex_home(host_codex, stage_dir):
    """A throwaway CODEX_HOME holding the operator's auth.json and CODEX_RUN_CONFIG; return its path."""
    dest = os.path.join(stage_dir, "_codex_home")
    os.makedirs(dest, exist_ok=True)
    shutil.copyfile(os.path.join(host_codex, "auth.json"), os.path.join(dest, "auth.json"))
    os.chmod(os.path.join(dest, "auth.json"), 0o600)
    with open(os.path.join(dest, "config.toml"), "w", encoding="utf-8") as f:
        f.write(CODEX_RUN_CONFIG)
    return dest


def stage_codex_marketplace(plugin_dir, stage_dir):
    """Build a local Codex marketplace around the host plugin dir; return the marketplace root.

    Codex installs a plugin from a marketplace: a directory with `.agents/plugins/marketplace.json`
    plus the plugin's files at `plugins/leoprevent`. The host plugin dir carries the host-arch
    bin/leoprevent-plugin, so the Stop hook binary the marketplace registers is runnable here.
    """
    mkt = os.path.join(stage_dir, "_codex_mkt")
    shutil.rmtree(mkt, ignore_errors=True)
    os.makedirs(os.path.join(mkt, ".agents", "plugins"))
    shutil.copytree(plugin_dir, os.path.join(mkt, "plugins", "leoprevent"),
                    ignore=shutil.ignore_patterns(".git"))
    manifest = {
        "name": "leotrace-local",
        "interface": {"displayName": "LeoTrace (local)"},
        "plugins": [{
            "name": "leoprevent",
            "source": {"source": "local", "path": "./plugins/leoprevent"},
            "policy": {"installation": "AVAILABLE"},
            "category": "Security",
        }],
    }
    with open(os.path.join(mkt, ".agents", "plugins", "marketplace.json"), "w",
              encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    return mkt


def codex_default_effort(model):
    """The model's own default reasoning effort, from Codex's model catalogue.

    ~/.codex/models_cache.json (kept current by the Codex CLI) lists default_reasoning_level per
    model: medium for the GPT-6 and GPT-5.6 models, xhigh for gpt-5.5 as of 2026-10-06. A run
    must name its model; a model missing from the catalogue is refused rather than guessed.
    """
    if not model:
        raise RuntimeError("Codex needs an explicit --codex_model: without it the model, and so its "
                           "default effort, come from the operator's config.toml")
    path = os.path.expanduser("~/.codex/models_cache.json")
    with open(path, encoding="utf-8") as f:
        catalogue = json.load(f)
    for m in catalogue.get("models", []):
        if isinstance(m, dict) and m.get("slug") == model and m.get("default_reasoning_level"):
            return m["default_reasoning_level"]
    raise RuntimeError(f"{model!r} has no default_reasoning_level in {path}; pass --codex_effort")
