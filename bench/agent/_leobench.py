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


_LEOPREVENT_STRIP_SECTIONS = ("marketplaces", "plugins", "hooks")


def strip_operator_leoprevent(config_text):
    """Drop the operator's own leoprevent registration from a copied Codex config.toml.

    The leoprevent arm installs the plugin itself; if the operator also has it installed in
    ~/.codex, copying config.toml verbatim registers it twice and the Stop hook fires twice
    (two reviews, findings double-counted). Walk the file table-block by table-block and drop a
    block that BOTH sits in a marketplaces/plugins/hooks section AND names leoprevent. Every
    other table and the preamble are kept verbatim.
    """
    blocks, cur = [], []
    for line in config_text.splitlines(keepends=True):
        if line.lstrip().startswith("["):
            blocks.append(cur)
            cur = [line]
        else:
            cur.append(line)
    blocks.append(cur)

    def keep(block):
        if not block or not block[0].lstrip().startswith("["):
            return True
        header = block[0].strip().lstrip("[").split(".", 1)[0].strip()
        in_scope = header in _LEOPREVENT_STRIP_SECTIONS
        names_leoprevent = "leoprevent" in "".join(block).lower()
        return not (in_scope and names_leoprevent)

    return "".join("".join(b) for b in blocks if keep(b))


def stage_codex_home(host_codex, stage_dir):
    """Copy auth.json + a sanitized config.toml into a throwaway CODEX_HOME; return its path."""
    dest = os.path.join(stage_dir, "_codex_home")
    os.makedirs(dest, exist_ok=True)
    for name in ("auth.json", "config.toml"):
        src = os.path.join(host_codex, name)
        if not os.path.isfile(src):
            continue
        out = os.path.join(dest, name)
        if name == "config.toml":
            with open(src, encoding="utf-8") as f:
                text = f.read()
            with open(out, "w", encoding="utf-8") as f:
                f.write(strip_operator_leoprevent(text))
        else:
            shutil.copyfile(src, out)
    auth = os.path.join(dest, "auth.json")
    if os.path.isfile(auth):
        os.chmod(auth, 0o600)
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
