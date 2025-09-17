# osigdetector/ingestion/effect_annotator.py
from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .ast_to_ucg import UCGBatch
from .repo_loader import FileRecord
from .provenance import Provenance, from_node, from_regex

# =============================================================================
# Effect data model (in-memory; persisted later via ucg_store)
# =============================================================================

@dataclass
class EffectRecord:
    effect_id: int
    file_rel: str
    func_qname: Optional[str]      # None for top-level/file-scoped detections
    effect_type: str               # route|db|external|schema|queue|scheduler|cli|guard|search|email|event
    lang: str
    framework_hint: str            # e.g., fastapi|flask|express|axios|requests|prisma|httpx|bull|celery
    raw_fields: Dict[str, str]     # method/path/table/topic/schema/model/action/url/etc.
    prov: Provenance
    anomalies: List[str] = field(default_factory=list)
    note: str = ""


@dataclass
class EffectsBundle:
    effects: List[EffectRecord]
    anomalies: List[Dict[str, str]] = field(default_factory=list)


# =============================================================================
# Annotator
# =============================================================================

class EffectAnnotator:
    """
    Conservative, evidence-first annotator for *pre-OSig* effect carriers.

    Evidence channels used:
      A) Call-edge identifiers (from SymbolResolver): e.dst_qname like "ident:axios.post"
      B) Source scan (per-file regex) for common routing declarations (FastAPI/Flask/Express)

    We DO NOT guess missing literals. Uncertain fields -> anomalies; keep auditable.
    """

    # ---- Common regexes for file-level route detection ----
    # FastAPI/Router decorators: @router.post("/path") or @app.get("/path")
    _PY_ROUTE_DECOR = re.compile(r"@(?:(?:router|app)\.)\s*(get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]", re.I)

    # Flask: @app.route("/path", methods=["GET", "POST"])
    _PY_FLASK_ROUTE = re.compile(
        r"@app\.route\(\s*['\"]([^'\"]+)['\"]\s*,\s*methods\s*=\s*\[\s*['\"]([A-Z]+)['\"]", re.I
    )

    # Express: app.get('/path', ...), router.post('/x', ...)
    _JS_EXPRESS_ROUTE = re.compile(
        r"\b(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]", re.I
    )

    # ---- Heuristic maps for call identifiers ----
    _HTTP_CLIENTS = {
        # ident prefix -> (framework, method-if-encodable)
        "axios.get": ("axios", "GET"),
        "axios.post": ("axios", "POST"),
        "axios.put": ("axios", "PUT"),
        "axios.delete": ("axios", "DELETE"),
        "fetch": ("fetch", ""),         # method may be in options
        "requests.get": ("requests", "GET"),
        "requests.post": ("requests", "POST"),
        "requests.put": ("requests", "PUT"),
        "requests.delete": ("requests", "DELETE"),
        "httpx.get": ("httpx", "GET"),
        "httpx.post": ("httpx", "POST"),
        "httpx.put": ("httpx", "PUT"),
        "httpx.delete": ("httpx", "DELETE"),
    }

    _DB_ACTIONS = {
        # Prisma style: prisma.user.create/update/find/delete/upsert
        # key is suffix after "prisma."
        "create": "create",
        "update": "update",
        "find": "read",
        "find_many": "read",
        "findFirst": "read",
        "delete": "delete",
        "upsert": "upsert",
        # SQL execution clues
        "cursor.execute": "sql_execute",
        "session.execute": "sql_execute",
    }

    _EVENT_PUBLISH = {
        "sns.publish": ("aws_sns", "publish"),
        "sqs.send_message": ("aws_sqs", "send"),
        "producer.send": ("kafka", "send"),
        "publisher.publish": ("generic", "publish"),
        "bus.publish": ("generic", "publish"),
    }

    _QUEUE_ENQUEUE = {
        "bull.add": ("bull", "enqueue"),
        "queue.add": ("bull", "enqueue"),
        "celery.send_task": ("celery", "send_task"),
    }

    _EMAIL_SEND = {
        "smtp.sendmail": ("smtp", "send"),
        "send_email": ("app", "send"),
        "mailer.send": ("mailer", "send"),
    }

    def __init__(self):
        self._next_effect_id = 1

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def annotate(self,
                 ucg: UCGBatch,
                 fn_nodes: Dict[str, object],        # present for parity; unused here but kept for API symmetry
                 file_meta: Dict[str, FileRecord]) -> EffectsBundle:
        """
        Build effect candidates from call edges and route scans.

        Args:
            ucg:       UCGBatch (functions/classes/edges with provenance)
            fn_nodes:  Mapping func_qname -> GenericNode (not required for current heuristics)
            file_meta: Map rel_path -> FileRecord (to read source text for route scans)

        Returns:
            EffectsBundle with effects and anomalies
        """
        effects: List[EffectRecord] = []
        anomalies: List[Dict[str, str]] = []

        # A) From call edges with identifiers
        for e in ucg.edges:
            if e.kind != "calls":
                continue
            ident = e.dst_qname or ""
            if not ident.startswith("ident:"):
                continue
            name = ident[len("ident:") :]

            # Normalize dotted names like axios.post / requests.get / prisma.user.create
            lowered = name.lower()

            # External HTTP calls
            for key, (fw, method) in self._HTTP_CLIENTS.items():
                if lowered.startswith(key):
                    effects.append(self._effect(
                        file_rel=e.file_rel,
                        func_qname=e.src_qname,  # caller scope
                        effect_type="external",
                        lang=self._lang_for_file(ucg, e.file_rel),
                        framework_hint=fw,
                        raw_fields={"method": method, "callee": name},
                        prov=self._prov_from_edge(e, note="external_http_call"),
                        note=e.note,
                    ))
                    break

            # Database operations (Prisma and generic SQL execute)
            # prisma.<model>.<action>
            if "prisma." in lowered:
                # try to extract model + action
                model, action = self._extract_prisma(lowered)
                effects.append(self._effect(
                    file_rel=e.file_rel,
                    func_qname=e.src_qname,
                    effect_type="db",
                    lang=self._lang_for_file(ucg, e.file_rel),
                    framework_hint="prisma",
                    raw_fields={"model": model or "", "action": action or ""},
                    prov=self._prov_from_edge(e, note="db_op"),
                    note=e.note,
                    anomalies=[] if model and action else ["PRISMA_PARSE_WEAK"],
                ))
            # SQL execute
            if lowered.startswith("cursor.execute") or lowered.startswith("session.execute"):
                effects.append(self._effect(
                    file_rel=e.file_rel,
                    func_qname=e.src_qname,
                    effect_type="db",
                    lang=self._lang_for_file(ucg, e.file_rel),
                    framework_hint="sql",
                    raw_fields={"action": "execute"},
                    prov=self._prov_from_edge(e, note="db_sql_execute"),
                    note=e.note,
                ))

            # Event publish
            for key, (fw, act) in self._EVENT_PUBLISH.items():
                if lowered.endswith(key):
                    effects.append(self._effect(
                        file_rel=e.file_rel,
                        func_qname=e.src_qname,
                        effect_type="event",
                        lang=self._lang_for_file(ucg, e.file_rel),
                        framework_hint=fw,
                        raw_fields={"action": act, "callee": name},
                        prov=self._prov_from_edge(e, note="event_publish"),
                        note=e.note,
                    ))

            # Queue enqueue / worker consume (enqueue only here)
            for key, (fw, act) in self._QUEUE_ENQUEUE.items():
                if lowered.endswith(key):
                    effects.append(self._effect(
                        file_rel=e.file_rel,
                        func_qname=e.src_qname,
                        effect_type="queue",
                        lang=self._lang_for_file(ucg, e.file_rel),
                        framework_hint=fw,
                        raw_fields={"action": act, "callee": name},
                        prov=self._prov_from_edge(e, note="queue_enqueue"),
                        note=e.note,
                    ))

            # Email send
            for key, (fw, act) in self._EMAIL_SEND.items():
                if lowered.endswith(key) or lowered.startswith(key):
                    effects.append(self._effect(
                        file_rel=e.file_rel,
                        func_qname=e.src_qname,
                        effect_type="email",
                        lang=self._lang_for_file(ucg, e.file_rel),
                        framework_hint=fw,
                        raw_fields={"action": act, "callee": name},
                        prov=self._prov_from_edge(e, note="email_send"),
                        note=e.note,
                    ))

        # B) From per-file scans (routes)
        for f in ucg.files:
            fr = file_meta.get(f.rel_path)
            if not fr:
                anomalies.append({"rel_path": f.rel_path, "reason": "MISSING_FILE_META_FOR_SCAN"})
                continue
            text = self._read_text(fr)
            if text is None:
                anomalies.append({"rel_path": f.rel_path, "reason": "IO_READ_FAILED_FOR_SCAN"})
                continue

            if f.language == "python":
                for m in self._PY_ROUTE_DECOR.finditer(text):
                    method = m.group(1).upper()
                    path = m.group(2)
                    effects.append(self._effect(
                        file_rel=f.rel_path,
                        func_qname=None,
                        effect_type="route",
                        lang="python",
                        framework_hint="fastapi",
                        raw_fields={"method": method, "path": path},
                        prov=self._prov_line(f.rel_path, self._line_of(text, m.start()), note="py_route_decorator"),
                    ))
                for m in self._PY_FLASK_ROUTE.finditer(text):
                    path = m.group(1)
                    method = m.group(2).upper()
                    effects.append(self._effect(
                        file_rel=f.rel_path,
                        func_qname=None,
                        effect_type="route",
                        lang="python",
                        framework_hint="flask",
                        raw_fields={"method": method, "path": path},
                        prov=self._prov_line(f.rel_path, self._line_of(text, m.start()), note="flask_route"),
                    ))

            if f.language in ("javascript", "typescript"):
                for m in self._JS_EXPRESS_ROUTE.finditer(text):
                    method = m.group(1).upper()
                    path = m.group(2)
                    effects.append(self._effect(
                        file_rel=f.rel_path,
                        func_qname=None,
                        effect_type="route",
                        lang=f.language,
                        framework_hint="express",
                        raw_fields={"method": method, "path": path},
                        prov=self._prov_line(f.rel_path, self._line_of(text, m.start()), note="express_route"),
                    ))

        return EffectsBundle(effects=effects, anomalies=anomalies)

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _effect(self,
                file_rel: str,
                func_qname: Optional[str],
                effect_type: str,
                lang: str,
                framework_hint: str,
                raw_fields: Dict[str, str],
                prov: Provenance,
                note: str = "",
                anomalies: Optional[List[str]] = None) -> EffectRecord:
        eid = self._next_effect_id
        self._next_effect_id += 1
        return EffectRecord(
            effect_id=eid,
            file_rel=file_rel,
            func_qname=func_qname,
            effect_type=effect_type,
            lang=lang,
            framework_hint=framework_hint,
            raw_fields=raw_fields,
            prov=prov,
            anomalies=anomalies or [],
            note=note,
        )

    def _lang_for_file(self, ucg: UCGBatch, file_rel: str) -> str:
        for f in ucg.files:
            if f.rel_path == file_rel:
                return f.language
        return "unknown"

    def _prov_from_edge(self, e, note: str) -> Provenance:
        return Provenance(
            file_rel=e.file_rel,
            start_line=e.prov.start_line,
            end_line=e.prov.end_line,
            start_byte=e.prov.start_byte,
            end_byte=e.prov.end_byte,
            note=note,
        )

    def _read_text(self, fr: FileRecord) -> Optional[str]:
        try:
            if fr.abs_locator.startswith("file://"):
                path = fr.abs_locator[len("file://") :]
                with open(path, "rb") as f:
                    data = f.read()
            elif fr.abs_locator.startswith("zip://"):
                rest = fr.abs_locator[len("zip://") :]
                if "!/" not in rest:
                    return None
                zip_path, inner = rest.split("!/", 1)
                with zipfile.ZipFile(zip_path, "r") as zf:
                    with zf.open(inner, "r") as f:
                        data = f.read()
            else:
                return None
        except Exception:
            return None

        try:
            return data.decode("utf-8", errors="replace")
        except Exception:
            return data.decode("latin-1", errors="replace")

    def _line_of(self, text: str, byte_offset: int) -> int:
        # Convert byte/char offset to 1-based line by counting newlines up to offset
        # Python's regex offsets are character offsets for the built-in 're' (not bytes)
        return text.count("\n", 0, byte_offset) + 1

    def _prov_line(self, file_rel: str, line: int, note: str) -> Provenance:
        return from_regex(file_rel=file_rel, line=line, note=note)

    def _extract_prisma(self, lowered_ident: str) -> Tuple[Optional[str], Optional[str]]:
        """
        From a string like 'prisma.user.create' or 'prisma.order.update', pull (model, action).
        """
        try:
            if not lowered_ident.startswith("prisma."):
                return None, None
            parts = lowered_ident.split(".")
            if len(parts) < 3:
                return None, None
            model = parts[1]
            action = parts[2]
            # Normalize common aliases
            action_norm = self._DB_ACTIONS.get(action, action)
            return model, action_norm
        except Exception:
            return None, None
