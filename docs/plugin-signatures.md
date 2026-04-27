# Plugin signature registry

Static analysis of a SecOps/Chronicle parser is grounded by a fixed set
of built-in plugin handlers (`grok`, `mutate`, `date`, `kv`, `json`,
`csv`, `dissect`, etc.). Anything outside that set — typically
org-specific custom enrichers, lookup plugins, or vendor-shipped
filters — falls through to the `unsupported_plugin` taint path: the
plugin's destinations are marked `unresolved` with a hard taint, and
queries against those fields return tainted lineage.

The plugin signature registry lets you teach the analyzer about custom
plugins via a small declarative TOML file. A registered signature
routes the plugin through a generic-but-sound handler that reads
declared `source_keys` and `dest_keys` from the plugin's config and
emits `signature_dispatched` lineage attributing the destinations back
to the resolved sources. The `unsupported_plugin` taint goes away;
you get derivable lineage instead.

## When to register a signature

- You have an internal plugin (`acme_geo_enrich`, `corp_threat_lookup`,
  etc.) whose source/destination fields you know.
- A vendor plugin's source/destination shape is documented and stable.
- A community plugin from elsewhere in the Logstash ecosystem behaves
  like one of the analyzer's built-in semantic classes
  (`extractor` / `enricher` / `transform` / `mutate_like` / `passthrough`).

If you don't know the plugin's shape — or if the plugin's behavior
depends on runtime data the analyzer can't observe — leave it
unsigned. The `unsupported_plugin` taint is the safe default.

## File format

Each top-level table is a `PluginSignature`. The table key supplies
the default `name` if the table omits one, so the simplest form is:

```toml
[acme_geo_enrich]
semantic_class = "enricher"
source_keys = ["source"]
dest_keys = ["target"]
```

Keys are validated by pydantic with `extra = "forbid"`. Typos in
`semantic_class`, `lineage_status`, or `taint_hint` raise a loud error
at load time so you discover them before the analyzer silently
degrades.

### Schema

| Key                | Type                                                    | Default     | Notes                                                                              |
|--------------------|---------------------------------------------------------|-------------|------------------------------------------------------------------------------------|
| `name`             | string                                                  | table key   | Plugin name as it appears in the parser (`acme_geo_enrich { ... }`).               |
| `semantic_class`   | `extractor` / `enricher` / `transform` / `mutate_like` / `passthrough` | required | Coarse category; see [Semantic classes](#semantic-classes) below.                   |
| `source_keys`      | list of strings                                         | `[]`        | Config keys whose values name source fields read by the plugin.                    |
| `dest_keys`        | list of strings                                         | `[]`        | Config keys whose values name destination fields written by the plugin.            |
| `dest_value_kind`  | `scalar` / `map` / `list`                               | `scalar`    | Shape of the value at each `dest_keys` entry. Maps treat keys as destinations.     |
| `in_place`         | bool                                                    | `false`     | Plugin mutates its source in place (advisory; reserved for future use).            |
| `lineage_status`   | `exact` / `derived` / `dynamic` / `conditional`         | `derived`   | Status assigned to emitted lineage. `conditional` is auto-applied under branches.  |
| `taint_hint`       | `none` / `derived` / `dynamic`                          | `derived`   | If non-`none`, attaches `signature_dispatched_<hint>` taint to each destination.   |

## Semantic classes

The `semantic_class` field is a coarse signal about *how* the plugin
relates to its inputs and outputs. v0.2 doesn't yet branch behavior
on it — every signature dispatches through the same generic handler —
but reviewers, tooling, and future PRs will use the class to decide
when finer-grained handling is appropriate.

- **`extractor`** — pulls structured fields out of an opaque blob.
  Examples: a custom JSON-shaped log decoder. `source_keys` should
  point at the raw blob field; `dest_keys` at the new fields produced.
- **`enricher`** — looks up additional facts about an existing field
  and writes derived data alongside it. Examples: GeoIP, threat
  intelligence, asset enrichment. `source_keys` is the input lookup
  key; `dest_keys` is where the lookup result lands.
- **`transform`** — reshapes a field in place or to a new field
  without external lookups. Examples: custom string normalization,
  hashing.
- **`mutate_like`** — behaves like Logstash's built-in `mutate`:
  destinations are usually a `replace` / `add_field` style map.
  Set `dest_value_kind = "map"` for these.
- **`passthrough`** — a no-op-from-the-analyzer's-perspective plugin
  that the user wants to silence. `lineage_status = "exact"` is common.

## Examples

### Enricher (single source → single destination)

```toml
[acme_geo_enrich]
semantic_class = "enricher"
source_keys = ["source"]
dest_keys = ["target"]
lineage_status = "derived"
taint_hint = "derived"
```

Use for a GeoIP-style plugin invoked as
`acme_geo_enrich { source => "client_ip" target => "principal.location.country" }`.
The destination's lineage will attribute back to `client_ip` with a
`signature_dispatched_derived` taint indicating the value was
synthesized via an unsigned plugin.

### Mutate-like (map of destinations → sources)

```toml
[corp_field_remap]
semantic_class = "mutate_like"
source_keys = []
dest_keys = ["replace"]
dest_value_kind = "map"
lineage_status = "exact"
taint_hint = "none"
```

Use for a plugin that takes a `replace => { dest => source, ... }`
map similar to Logstash's built-in `mutate { replace => ... }`.
Destinations come from the map keys; **each destination's lineage is
attributed to the plugin-scope `source_keys` plus the pair's specific
RHS source** — so `dst1 => "%{x}"` and `dst2 => "%{y}"` produce
distinct upstream attributions, not the union of `x` and `y`.

### Fan-out enricher (single source → list of destinations)

```toml
[fanout_enricher]
semantic_class = "enricher"
source_keys = ["source"]
dest_keys = ["targets"]
dest_value_kind = "list"
lineage_status = "derived"
taint_hint = "derived"
```

Use for a plugin invoked as
`fanout_enricher { source => "client_ip" targets => ["principal.ip", "src.geo.country"] }`.
Each entry in the list becomes a destination, attributed back to the
plugin-scope `source_keys`. **Without `dest_value_kind = "list"`**
the handler treats a non-pairs list as a misshapen map and silently
ignores it — explicit declaration disambiguates intent.

### Passthrough (analyzer should ignore)

```toml
[debug_only_logger]
semantic_class = "passthrough"
source_keys = []
dest_keys = []
taint_hint = "none"
```

Use for a development-time-only logger or any plugin whose effect on
the data flow is nil.

## Loading signatures

### CLI

```sh
parser-lineage-analyzer my_parser.cbn target.field \
  --plugin-signatures team-defaults.toml \
  --plugin-signatures-dir ./signatures
```

Both flags are repeatable. Directories load every `*.toml` file
within them in sorted-name order; individual `--plugin-signatures`
files load after directories. Last-write-wins on duplicate `name`
across the entire load order.

### Programmatic

```python
from pathlib import Path
from parser_lineage_analyzer import ReverseParser
from parser_lineage_analyzer._plugin_signatures import PluginSignatureRegistry

registry = PluginSignatureRegistry.from_paths(
    files=[Path("signatures/override.toml")],
    directories=[Path("signatures/defaults")],
)
parser = ReverseParser(open("my_parser.cbn").read(), plugin_signatures=registry)
parser.analyze()
```

## Soundness contract

A signature is a *shape* declaration, not a behavioral spec. The
generic handler emits `signature_dispatched` lineage for every
declared destination, attributing it to the resolved sources of the
declared `source_keys`. It does NOT attempt to model the plugin's
real semantics — if the plugin internally transforms or filters the
data in a way that affects which UDM field actually gets written,
the attribution may be approximate.

Two safety nets:

1. **Lookup miss is sound.** When no signature matches the plugin
   name, the analyzer falls through to the existing
   `unsupported_plugin` taint path. Pre-F3 behavior is preserved
   byte-for-byte.

2. **Validation errors are loud.** Pydantic `extra = "forbid"` plus
   `Literal[...]` enums on the type-fields catch typos at TOML load
   time. A misspelled `semantic_class` raises `ValueError` rather
   than silently registering a partial signature.

## Bundled signatures

The package ships a small audited bundle under
`parser_lineage_analyzer/plugin_signatures/`. These signatures are
conservative and are not loaded unless a caller explicitly uses
`load_bundled_registry()` or passes them through the existing
signature-loading path.

Bundled signatures are intentionally approximate: they reduce hard
`unsupported_plugin` output for common opaque enrichers, while dynamic
or external behavior remains tainted. For organization-specific plugins,
prefer loading your own audited `--plugin-signatures` files.
