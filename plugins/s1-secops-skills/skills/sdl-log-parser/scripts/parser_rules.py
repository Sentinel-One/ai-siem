"""Offline lint rules for SDL log parsers (the augmented-JSON files at /logParsers/).

Standard library only, so it runs inside a plugin install with no dependencies.

Every rule encodes a trap documented in this skill's SKILL.md (or a reference it
links), and names the section it comes from in `ref`. A rule is added here only
when the skill already records the behaviour as tenant-validated; the lint never
invents platform behaviour.

What this does NOT do: it does not run the parser. The SDL parser engine is
server-side and has no local equivalent, so a clean lint means "none of the known
traps are present", never "this parser parses". Deploy and validate live (SKILL.md,
workflow step 5) before calling a parser done.

Every rule was checked against the live parser engine on 2026-10-13 with a
known-bad and known-good parser pair (deploy, HEC ingest, query back). That run
corrected three earlier assumptions: v0 `constants` fail only when keyed `output`
(R03), a same-name rename nulls the field on v1 only (R06), and a lazy prefix
fails only when nothing anchors it (R10). It also showed that when no format
matches an event, the parser's root attributes are not applied either, so R01,
R10 and R11 failures leave the event with no parser attributes at all.

This module is the single source of truth for parser-shape checks. The skill's
eval grader (`tools/run_evals.py`, assertion type `lint_clean`) imports it rather
than restating the same regexes.

Use:
    from parser_rules import lint_text
    findings = lint_text(source_text, name="myparser.conf")
"""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

__all__ = [
    "Finding", "Rule", "RULES", "SEVERITIES", "ParseError",
    "load_augmented_json", "lint_text", "lint_obj", "OFFLINE_DISCLAIMER",
]

SEVERITIES = ("ERROR", "WARN", "INFO")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

OFFLINE_DISCLAIMER = (
    "Offline lint checks known traps only. It does not prove the parser parses: "
    "deploy it and validate on the live stream (or the synthetic-ingest fallback) "
    "before calling it done."
)


# ---------------------------------------------------------------------------
# Augmented-JSON reader
# ---------------------------------------------------------------------------
# SDL parser files are "augmented JSON": // and /* */ comments, unquoted keys,
# single- or double-quoted strings, "a" + "b" string concatenation, trailing
# commas, and (tolerated here) missing commas between members. `#` is NOT a
# comment, so a placeholder file of `#` lines is reported as unparseable. The reader records the source line of every
# value by its path, so findings can point at a line.

class ParseError(ValueError):
    def __init__(self, msg: str, line: int):
        super().__init__(f"line {line}: {msg}")
        self.line = line


_IDENT = re.compile(r"[A-Za-z0-9_$.\-@]+")
_NUM = re.compile(r"-?(?:0[xX][0-9a-fA-F]+|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)")
_SIMPLE_ESC = {'"': '"', "'": "'", "\\": "\\", "/": "/", "b": "\b",
               "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


class _Reader:
    def __init__(self, text: str):
        self.s = text
        self.i = 0
        self.n = len(text)
        self.lines: dict[str, int] = {}
        self._nl = [i for i, ch in enumerate(text) if ch == "\n"]

    def line(self, pos: int | None = None) -> int:
        return bisect.bisect_left(self._nl, self.i if pos is None else pos) + 1

    def ws(self) -> None:
        s, n = self.s, self.n
        while self.i < n:
            c = s[self.i]
            if c in " \t\r\n﻿":
                self.i += 1
            elif s.startswith("//", self.i):
                j = s.find("\n", self.i)
                self.i = n if j < 0 else j + 1
            elif s.startswith("/*", self.i):
                j = s.find("*/", self.i + 2)
                if j < 0:
                    raise ParseError("unterminated /* comment", self.line())
                self.i = j + 2
            else:
                return

    def value(self, path: str) -> Any:
        self.ws()
        if self.i >= self.n:
            raise ParseError("unexpected end of input", self.line())
        self.lines.setdefault(path, self.line())
        c = self.s[self.i]
        if c == "{":
            return self.obj(path)
        if c == "[":
            return self.arr(path)
        if c in "\"'":
            # Augmented JSON allows string concatenation: "a" + "b".
            out = self.string()
            while True:
                save = self.i
                self.ws()
                if self.i < self.n and self.s[self.i] == "+":
                    self.i += 1
                    self.ws()
                    if self.i < self.n and self.s[self.i] in "\"'":
                        out += self.string()
                        continue
                    raise ParseError("'+' not followed by a string", self.line())
                self.i = save
                return out
        m = _NUM.match(self.s, self.i)
        if m and (m.end() == self.n or not _IDENT.match(self.s[m.end()])):
            self.i = m.end()
            t = m.group(0)
            if t.lower().startswith(("0x", "-0x")):
                return int(t, 16)
            return float(t) if any(ch in t for ch in ".eE") else int(t)
        m = _IDENT.match(self.s, self.i)
        if m:
            self.i = m.end()
            word = m.group(0)
            return {"true": True, "false": False, "null": None}.get(word, word)
        raise ParseError(f"unexpected character {c!r}", self.line())

    def string(self) -> str:
        q = self.s[self.i]
        start_line = self.line()
        self.i += 1
        out = []
        s, n = self.s, self.n
        while self.i < n:
            c = s[self.i]
            if c == q:
                self.i += 1
                return "".join(out)
            if c == "\\" and self.i + 1 < n:
                e = s[self.i + 1]
                if e in _SIMPLE_ESC:
                    out.append(_SIMPLE_ESC[e])
                    self.i += 2
                elif e == "u" and re.match(r"[0-9a-fA-F]{4}", s[self.i + 2:self.i + 6]):
                    out.append(chr(int(s[self.i + 2:self.i + 6], 16)))
                    self.i += 6
                elif e == "\n":
                    self.i += 2  # line continuation
                else:
                    # Unknown escape: keep it verbatim so regex text survives.
                    out.append("\\" + e)
                    self.i += 2
                continue
            out.append(c)
            self.i += 1
        raise ParseError("unterminated string", start_line)

    def key(self) -> str:
        self.ws()
        if self.i < self.n and self.s[self.i] in "\"'":
            return self.string()
        m = _IDENT.match(self.s, self.i)
        if not m:
            raise ParseError(f"expected a key, found {self.s[self.i:self.i+1]!r}",
                             self.line())
        self.i = m.end()
        return m.group(0)

    def obj(self, path: str) -> dict:
        self.i += 1
        out: dict = {}
        while True:
            self.ws()
            if self.i >= self.n:
                raise ParseError("unterminated object", self.line())
            if self.s[self.i] == "}":
                self.i += 1
                return out
            if self.s[self.i] == ",":
                self.i += 1
                continue
            k = self.key()
            self.ws()
            if self.i >= self.n or self.s[self.i] != ":":
                raise ParseError(f"expected ':' after key {k!r}", self.line())
            self.i += 1
            out[k] = self.value(f"{path}.{k}" if path else k)

    def arr(self, path: str) -> list:
        self.i += 1
        out: list = []
        while True:
            self.ws()
            if self.i >= self.n:
                raise ParseError("unterminated array", self.line())
            if self.s[self.i] == "]":
                self.i += 1
                return out
            if self.s[self.i] == ",":
                self.i += 1
                continue
            out.append(self.value(f"{path}[{len(out)}]"))


def load_augmented_json(text: str) -> tuple[Any, dict[str, int]]:
    """Parse augmented JSON. Returns (value, {path: line})."""
    r = _Reader(text)
    r.ws()
    if r.i >= r.n:
        raise ParseError("no parser content (the file is empty or comments only)", r.line())
    v = r.value("")
    r.ws()
    if r.i < r.n:
        raise ParseError("trailing content after the top-level value", r.line())
    return v, r.lines


# ---------------------------------------------------------------------------
# Findings and rules
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    rule: str
    severity: str
    path: str
    message: str
    ref: str
    line: int | None = None

    def as_dict(self) -> dict:
        return {"rule": self.rule, "severity": self.severity, "path": self.path,
                "line": self.line, "message": self.message, "ref": self.ref}


@dataclass
class Rule:
    id: str
    severity: str
    title: str
    ref: str
    check: Callable[["_Ctx"], Iterable[tuple[str, str]]] = field(repr=False)


@dataclass
class _Ctx:
    obj: dict
    new: bool  # authoring a new parser (stricter on metadata.version)


def _formats(o: dict) -> list[tuple[str, dict]]:
    out = []
    for i, f in enumerate(o.get("formats") or []):
        if isinstance(f, dict):
            out.append((f"formats[{i}]", f))
    return out


def _all_regex_strings(o: dict) -> list[tuple[str, str]]:
    """Every string that the engine treats as a format or regex."""
    out = []
    for p, f in _formats(o):
        if isinstance(f.get("format"), str):
            out.append((f"{p}.format", f["format"]))
        for j, rw in enumerate(f.get("rewrites") or []):
            if isinstance(rw, dict) and isinstance(rw.get("match"), str):
                out.append((f"{p}.rewrites[{j}].match", rw["match"]))
    for k, v in (o.get("patterns") or {}).items():
        if isinstance(v, str):
            out.append((f"patterns.{k}", v))
    for i, g in enumerate(o.get("lineGroupers") or []):
        if isinstance(g, dict):
            for k in ("start", "continueThrough", "continuePast", "haltBefore", "haltWith"):
                if isinstance(g.get(k), str):
                    out.append((f"lineGroupers[{i}].{k}", g[k]))
    return out


def _inline_regexes(fmt: str) -> list[str]:
    """The `{regex=...}` bodies inside a format string."""
    out = []
    for m in re.finditer(r"\{regex=", fmt):
        depth, j = 1, m.end()
        while j < len(fmt) and depth:
            if fmt[j] == "\\":
                j += 2
                continue
            depth += {"{": 1, "}": -1}.get(fmt[j], 0)
            j += 1
        out.append(fmt[m.end():j - 1])
    return out


def _mapping_entries(o: dict) -> tuple[int | None, list[tuple[str, dict]]]:
    m = o.get("mappings")
    if not isinstance(m, dict):
        return None, []
    ver = m.get("version")
    entries = [(f"mappings.mappings[{i}]", e)
               for i, e in enumerate(m.get("mappings") or []) if isinstance(e, dict)]
    return ver, entries


def _is_always_true(pred: Any) -> bool:
    return pred is True or (isinstance(pred, str)
                            and pred.strip().lower() in ("true", "1==1", "1 == 1"))


def _walk_strings(v: Any, path: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(v, str):
        yield path, v
    elif isinstance(v, dict):
        for k, x in v.items():
            yield from _walk_strings(x, f"{path}.{k}" if path else k)
    elif isinstance(v, list):
        for i, x in enumerate(v):
            yield from _walk_strings(x, f"{path}[{i}]")


KV = "$_=identifier$=$_=quoteOrSpace$"


# --- rule bodies ----------------------------------------------------------

def r01_kv_leading_dotstar(c: _Ctx):
    for p, f in _formats(c.obj):
        fmt = f.get("format")
        if isinstance(fmt, str) and KV in fmt and not fmt.startswith(".*"):
            idx = fmt.find(KV)
            if fmt[max(0, idx - 2):idx] != ".*":
                yield (f"{p}.format",
                       "key=value catch-all has no leading `.*`: it anchors at position 0 "
                       "and captures nothing on lines starting with a priority, CEF header "
                       "or timestamp. Use \".*$_=identifier$=$_=quoteOrSpace$\".")


def r02_kv_repeat(c: _Ctx):
    for p, f in _formats(c.obj):
        fmt = f.get("format")
        # Only the canonical catch-all idiom. Positional `$_=identifier$` captures
        # (a fixed number of pairs) and explicit `repeat: false` last-value formats
        # are deliberate and are not flagged.
        if (isinstance(fmt, str) and KV in fmt and "repeat" not in f):
            yield (f"{p}.repeat",
                   "key=value catch-all without `repeat: true` captures only the first pair.")


def r03_v0_constants(c: _Ctx):
    # Live-validated 2026-10-13: a v0 constant keyed `field` deploys and applies;
    # the same constant keyed `output` (the shape v0 renames/copies use) is
    # rejected by putFile ("Content is invalid json" / "Expected a field").
    ver, entries = _mapping_entries(c.obj)
    if ver == 0:
        for p, e in entries:
            for j, k in enumerate(e.get("constants") or []):
                if isinstance(k, dict) and "output" in k and "field" not in k:
                    yield (f"{p}.constants[{j}]",
                           "v0 constant keyed `output`: putFile rejects it. v0 constants take "
                           "`field` (unlike v0 renames/copies, which take `output`).")


def r04_v1_version(c: _Ctx):
    m = c.obj.get("mappings")
    if isinstance(m, dict) and m.get("mappings") and "version" not in m:
        yield ("mappings.version",
               "`mappings` has no `version`: the tenant returns 'unsupported event "
               "mapper version -1'. Set `version: 1` (or 0 for a v0 body).")
    elif isinstance(m, dict) and m.get("version") not in (None, 0, 1):
        yield ("mappings.version", f"`mappings.version` is {m.get('version')!r}; only 0 and 1 exist.")


def _emitted_fields(o: dict) -> set[str]:
    """Field names the parser writes: attributes, format captures, mapping outputs."""
    names: set[str] = set()
    for k in (o.get("attributes") or {}):
        names.add(k)
    for p, f in _formats(o):
        for k in (f.get("attributes") or {}):
            names.add(k)
        fmt = f.get("format")
        if isinstance(fmt, str):
            for m in re.finditer(r"\$([A-Za-z_][\w.]*)(?=[$={])", fmt):
                names.add(m.group(1))
    _, entries = _mapping_entries(o)
    for _, e in entries:
        for t in e.get("transformations") or []:
            if isinstance(t, dict):
                for body in t.values():
                    if isinstance(body, dict):
                        for k in ("to", "field"):
                            if isinstance(body.get(k), str):
                                names.add(body[k])
        for op in ("renames", "copies", "constants"):
            for t in e.get(op) or []:
                if isinstance(t, dict):
                    for k in ("output", "field"):
                        if isinstance(t.get(k), str):
                            names.add(t[k])
    return names


def r05_severity(c: _Ctx):
    names = _emitted_fields(c.obj)
    if "severity" in names and "severity_id" in names:
        yield ("",
               "parser writes both reserved `severity` (coerced to 0-6) and `severity_id`. "
               "Emit `severity_id` (int) and put the vendor string in `severity_name`.")


def r06_same_name_rename(c: _Ctx):
    _, entries = _mapping_entries(c.obj)
    for p, e in entries:
        for j, t in enumerate(e.get("transformations") or []):
            if isinstance(t, dict) and isinstance(t.get("rename"), dict):
                b = t["rename"]
                if b.get("from") is not None and b.get("from") == b.get("to"):
                    yield (f"{p}.transformations[{j}].rename",
                           f"same-name rename of `{b['from']}` silently nulls the field; "
                           "omit it to keep the value.")
        # v0 `renames` with inputs == output are NOT flagged: live-validated
        # 2026-10-13, a same-name v0 rename keeps the value (only v1 nulls it).


def r07_catchall_not_last(c: _Ctx):
    _, entries = _mapping_entries(c.obj)
    for idx, (p, e) in enumerate(entries[:-1]):
        if _is_always_true(e.get("predicate")):
            yield (f"{p}.predicate",
                   f"always-true catch-all is entry {idx} of {len(entries)}: mappings are "
                   "first-match-wins, so every entry after it never fires. Move it last.")


def r08_trailing_dotstar(c: _Ctx):
    for p, f in _formats(c.obj):
        fmt = f.get("format")
        if isinstance(fmt, str) and re.search(r"\{regex=\.\*\}\$\s*$", fmt):
            yield (f"{p}.format",
                   "format ends with `{regex=.*}$`: SDL strips the `.*`, so the field "
                   "captures an empty string. Use `[\\s\\S]+` or `[\\s\\S]*`.")


def r09_leading_lazy_dotstar(c: _Ctx):
    for p, s in _all_regex_strings(c.obj):
        bodies = _inline_regexes(s) if p.endswith(".format") else [s]
        for b in bodies:
            if b.startswith(".*?"):
                yield (p, "regex starts with `.*?`: SDL strips the leading `.*` and the Java "
                          "engine rejects the orphaned `?` ('Dangling meta character'). Use "
                          "greedy `[\\s\\S]*` plus a literal anchor.")


def r10_lazy_class_prefix(c: _Ctx):
    for p, s in _all_regex_strings(c.obj):
        bodies = _inline_regexes(s) if p.endswith(".format") else [s]
        for b in bodies:
            # Only a lazy capture with nothing after it in its own regex. With a
            # literal anchor inside (`[\s\S]*?COMMAND=`) it works: live 2026-10-13.
            if b in ("[\\s\\S]*?", "[\\S\\s]*?"):
                yield (p, "anchorless lazy `[\\s\\S]*?` capture: the engine does not backtrack "
                          "across field boundaries, so it matches almost nothing. Put a literal "
                          "anchor inside the regex, or use greedy `[\\s\\S]*` plus an anchor.")


def _alternation_groups(regex: str) -> list[list[str]]:
    """Top-level `a|b|c` and `(a|b|c)` alternatives made only of literal words."""
    groups = []
    for m in re.finditer(r"\((?:\?:)?([A-Za-z0-9_\-|]+)\)", regex):
        groups.append(m.group(1).split("|"))
    if re.fullmatch(r"[A-Za-z0-9_\-]+(?:\|[A-Za-z0-9_\-]+)+", regex):
        groups.append(regex.split("|"))
    return groups


def _used_patterns(o: dict) -> set[str]:
    used: set[str] = set()
    for _, f in _formats(o):
        fmt = f.get("format")
        if isinstance(fmt, str):
            used.update(re.findall(r"\$[\w.\-]*=([A-Za-z_]\w*)\$", fmt))
    return used


def r11_alternation_order(c: _Ctx):
    for p, s in _all_regex_strings(c.obj):
        # The no-backtrack behaviour is at FIELD boundaries (inline {regex=} and
        # named patterns). A rewrite `match` is one Java regex that backtracks
        # normally, so it is not checked.
        if ".rewrites[" in p:
            continue
        # A named pattern only matters if some format uses it ($field=name$).
        if p.startswith("patterns.") and p.split(".", 1)[1] not in _used_patterns(c.obj):
            continue
        bodies = _inline_regexes(s) if p.endswith(".format") else [s]
        for b in bodies:
            for alts in _alternation_groups(b):
                for i, a in enumerate(alts):
                    for later in alts[i + 1:]:
                        if a and later != a and later.startswith(a):
                            yield (p, f"alternation `{a}` comes before `{later}`: alternatives "
                                      "match in declaration order, so the longer one never "
                                      "matches. Put the longer alternative first.")
                            break


def r12_root_discard_of_scratch(c: _Ctx):
    root = c.obj.get("discardAttributes") or []
    if not isinstance(root, list):
        return
    scratch = [a for a in root if isinstance(a, str) and a.startswith("_")]
    if not scratch:
        return
    per_format: set[str] = set()
    for _, f in _formats(c.obj):
        per_format.update(a for a in (f.get("discardAttributes") or []) if isinstance(a, str))
    leaked = [a for a in scratch if a not in per_format]
    if leaked:
        yield ("discardAttributes",
               f"scratch capture(s) {', '.join(sorted(leaked))} discarded only at parser root: "
               "root scope does not reliably drop format captures. Put them in the "
               "format's own `discardAttributes`.")


def r13_escaped_dots_in_from(c: _Ctx):
    _, entries = _mapping_entries(c.obj)
    for p, e in entries:
        for j, t in enumerate(e.get("transformations") or []):
            if isinstance(t, dict):
                for op, body in t.items():
                    if isinstance(body, dict):
                        srcs = body.get("from")
                        for s in (srcs if isinstance(srcs, list) else [srcs]):
                            if isinstance(s, str) and "\\." in s:
                                yield (f"{p}.transformations[{j}].{op}.from",
                                       f"`{s}` escapes dots: gron/dottedJson keys are flat, so "
                                       "the escaped form does not match. Write the dotted name plainly.")


def _attr_sources(o: dict) -> list[tuple[str, dict]]:
    """Root attributes plus every format's attributes (a parser may set the
    dataSource attributes per format, e.g. one parser for several products)."""
    out = [("attributes", o.get("attributes") or {})]
    for p, f in _formats(o):
        if isinstance(f.get("attributes"), dict):
            out.append((f"{p}.attributes", f["attributes"]))
    return [(p, a) for p, a in out if isinstance(a, dict)]


def r14_required_attributes(c: _Ctx):
    if "aliasTo" in c.obj:
        return
    emitted = _emitted_fields(c.obj)
    for k in ("dataSource.name", "dataSource.vendor", "dataSource.category"):
        if k not in emitted:
            yield (f"attributes.{k}", f"mandatory attribute `{k}` is never set (not at the "
                                      "root, on a format, or by a mapping).")


def r15_category_security(c: _Ctx):
    for p, a in _attr_sources(c.obj):
        v = a.get("dataSource.category")
        if v is not None and v != "security":
            yield (f"{p}.dataSource.category",
                   f"`dataSource.category` is {v!r}; it is a fixed constant and must be \"security\".")


def r16_metadata_version(c: _Ctx):
    if "aliasTo" in c.obj:
        return
    attrs = c.obj.get("attributes") or {}
    v = attrs.get("metadata.version")
    if v is None:
        yield ("attributes.metadata.version",
               "no `metadata.version`: without it you cannot tell from the live stream which "
               "parser version parsed an event. Add a semver and bump it on every deploy.")
    elif not (isinstance(v, str) and re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?", v)):
        yield ("attributes.metadata.version", f"`metadata.version` {v!r} is not semver (MAJOR.MINOR.PATCH).")


def r17_claude_test(c: _Ctx):
    for p, s in _walk_strings(c.obj):
        if "claude_test_" in s:
            yield (p, "`claude_test_*` throwaway name: deploy to the real parser name instead.")
            return


def r18_syslog_priority(c: _Ctx):
    for p, s in _all_regex_strings(c.obj):
        if "{parse=syslogPriority}" in s:
            yield (p, "`{parse=syslogPriority}` has caused silent event drops on some tenants. "
                      "If events go missing, capture the priority as `$pri{regex=\\d+}$` instead.")


V1_OPS = {"rename", "copy", "cast", "constant", "drop", "drop_tree", "copy_tree",
          "rename_tree", "hash", "reduce_array", "replace", "zip"}


def r19_transformation_one_key(c: _Ctx):
    # Live 2026-10-13: putFile 400 "Expected one entry in object in
    # 'transformations' array" for an entry carrying a "_comment" key.
    ver, entries = _mapping_entries(c.obj)
    if ver != 1:
        return
    for p, e in entries:
        for j, t in enumerate(e.get("transformations") or []):
            if isinstance(t, dict) and len(t) != 1:
                yield (f"{p}.transformations[{j}]",
                       f"transformation entry has {len(t)} keys ({', '.join(sorted(t))}); "
                       "each entry must hold exactly one op. Use // comments, not a "
                       "\"_comment\" key.")


def r20_unknown_op(c: _Ctx):
    # Live 2026-10-13: putFile 400 "Unsupported transformation 'regex'".
    ver, entries = _mapping_entries(c.obj)
    if ver != 1:
        return
    for p, e in entries:
        for j, t in enumerate(e.get("transformations") or []):
            if isinstance(t, dict) and len(t) == 1:
                op = next(iter(t))
                if op not in V1_OPS and not op.startswith("_"):
                    yield (f"{p}.transformations[{j}]",
                           f"unsupported v1 transformation `{op}`; supported: "
                           f"{', '.join(sorted(V1_OPS))}. A regex rewrite belongs in "
                           "the format's `rewrites`.")


def r21_name_specifier(c: _Ctx):
    # Live 2026-10-13: putFile 400 'Unknown option "name" for attribute specifier'.
    for p, f in _formats(c.obj):
        fmt = f.get("format")
        if isinstance(fmt, str) and "{name=" in fmt:
            yield (f"{p}.format",
                   "`{name=...}` is not a field-matcher option. To capture with a named "
                   "pattern use `$field=pattern$`.")


def r22_empty_brackets_in_predicate(c: _Ctx):
    # Live 2026-10-13: putFile 400 "Don't understand [[] -- try enclosing it in quotes".
    _, entries = _mapping_entries(c.obj)
    for p, e in entries:
        preds = [(f"{p}.predicate", e.get("predicate"))]
        for j, t in enumerate(e.get("transformations") or []):
            if isinstance(t, dict):
                for op, body in t.items():
                    if isinstance(body, dict):
                        preds.append((f"{p}.transformations[{j}].{op}.predicate",
                                      body.get("predicate")))
        for path, pred in preds:
            if isinstance(pred, str) and "[]" in pred:
                yield (path, "`[]` in a predicate is rejected on deploy. Reference an "
                             "indexed element (`[0]`) or a flattened field.")


RULES: list[Rule] = [
    Rule("R01", "ERROR", "key=value catch-all missing leading .*",
         "SKILL.md: Critical pitfalls #1", r01_kv_leading_dotstar),
    Rule("R02", "ERROR", "key=value catch-all missing repeat: true",
         "SKILL.md: Critical pitfalls #1", r02_kv_repeat),
    Rule("R03", "ERROR", "v0 constant keyed `output` (rejected by putFile)",
         "SKILL.md: Critical pitfalls #3", r03_v0_constants),
    Rule("R04", "ERROR", "mappings without a valid version",
         "SKILL.md: mappings block gotchas (v1)", r04_v1_version),
    Rule("R05", "ERROR", "emits both severity and severity_id",
         "SKILL.md: reserved severity field", r05_severity),
    Rule("R06", "ERROR", "same-name v1 rename nulls the field",
         "SKILL.md: Critical pitfalls #4", r06_same_name_rename),
    Rule("R07", "ERROR", "always-true mapping entry is not last",
         "SKILL.md: v1 mappings are first-match-wins; references/mappers.md", r07_catchall_not_last),
    Rule("R08", "ERROR", "format ends with {regex=.*}$ (captures empty)",
         "SKILL.md: trailing .* is stripped", r08_trailing_dotstar),
    Rule("R09", "ERROR", "regex starts with .*? (dangling meta character)",
         "SKILL.md: leading .* is stripped", r09_leading_lazy_dotstar),
    Rule("R10", "ERROR", "anchorless lazy [\\s\\S]*? capture",
         "SKILL.md: lazy [\\s\\S]*? prefix matches almost nothing", r10_lazy_class_prefix),
    Rule("R11", "ERROR", "alternation not longest-first",
         "SKILL.md: regex alternation matches in declaration order", r11_alternation_order),
    Rule("R12", "WARN", "scratch captures discarded only at root",
         "SKILL.md: discardAttributes must be per-format", r12_root_discard_of_scratch),
    Rule("R13", "ERROR", "escaped dots in a mapping source",
         "SKILL.md: gron-captured dotted keys are flat", r13_escaped_dots_in_from),
    Rule("R14", "WARN", "mandatory dataSource attribute missing",
         "SKILL.md: Rule 1, the mandatory attributes", r14_required_attributes),
    Rule("R15", "WARN", "dataSource.category is not \"security\"",
         "SKILL.md: dataSource.category MUST always be \"security\"", r15_category_security),
    Rule("R16", "INFO", "metadata.version missing or not semver",
         "SKILL.md: metadata.version is mandatory, semver", r16_metadata_version),
    Rule("R17", "ERROR", "claude_test_ throwaway name",
         "SKILL.md: Validation, deploy to the real parser name", r17_claude_test),
    Rule("R18", "INFO", "{parse=syslogPriority} in use",
         "SKILL.md: syslogPriority can cause silent drops", r18_syslog_priority),
    Rule("R19", "ERROR", "v1 transformation entry with more than one key",
         "SKILL.md: mappings block gotchas (v1)", r19_transformation_one_key),
    Rule("R20", "ERROR", "unsupported v1 transformation op",
         "references/mappers.md: Operations", r20_unknown_op),
    Rule("R21", "ERROR", "{name=...} field-matcher option",
         "SKILL.md: Field-matcher syntax inside a format string", r21_name_specifier),
    Rule("R22", "ERROR", "[] in a mapping predicate",
         "SKILL.md: mappings block gotchas", r22_empty_brackets_in_predicate),
]

RULES_BY_ID = {r.id: r for r in RULES}


def _effective_severity(rule: Rule, ctx: _Ctx) -> str:
    # For a parser being authored now, these are hard-rule violations. For an
    # inherited catalog parser they are findings to fix on the next edit.
    if ctx.new and rule.id in ("R14", "R15", "R16"):
        return "ERROR"
    return rule.severity


def lint_obj(obj: Any, lines: dict[str, int] | None = None, *, new: bool = False,
             only: Iterable[str] | None = None) -> list[Finding]:
    lines = lines or {}
    if not isinstance(obj, dict):
        return [Finding("R00", "ERROR", "", "top-level value is not an object", "SKILL.md: syntax")]
    ctx = _Ctx(obj=obj, new=new)
    wanted = set(only) if only else None
    out: list[Finding] = []
    for rule in RULES:
        if wanted and rule.id not in wanted:
            continue
        for hit in rule.check(ctx):
            path, msg = hit[0], hit[1]
            sev = hit[2] if len(hit) > 2 else _effective_severity(rule, ctx)
            line = lines.get(path)
            if line is None:
                # Fall back to the nearest recorded ancestor path.
                q = path
                while q and line is None:
                    parent = re.sub(r"(\.[^.\[]+|\[\d+\])$", "", q)
                    q = "" if parent == q else parent
                    line = lines.get(q)
            out.append(Finding(rule.id, sev, path, msg, rule.ref, line))
    return out


def lint_text(text: str, *, new: bool = False, only: Iterable[str] | None = None) -> list[Finding]:
    """Lint parser source text. A file that does not parse yields one R00 finding."""
    try:
        obj, lines = load_augmented_json(text)
    except ParseError as e:
        return [Finding("R00", "ERROR", "", f"does not parse as augmented JSON: {e}",
                        "references/syntax.md", e.line)]
    return lint_obj(obj, lines, new=new, only=only)
