"""Gate de scope: el componente de seguridad mas importante.

Decide si un host/URL esta AUTORIZADO. out_of_scope tiene prioridad sobre
in_scope. Formatos de patron admitidos (in_scope y out_of_scope):

  ejemplo.com                  host exacto, cualquier puerto y ruta
  *.ejemplo.com                cualquier subdominio; el apex SOLO si
                               rules.wildcard_includes_apex=true
  ejemplo.com:8443             solo ese puerto
  https://ejemplo.com/api/     solo esa ruta (y lo que cuelga de ella); el esquema
                               fija el puerto por defecto (https=443, http=80)
  203.0.113.10 | 203.0.113.0/24 | [2001:db8::1]:8080
                               IP o rango CIDR. Solo casa con objetivos escritos
                               como IP: un hostname NUNCA se resuelve por DNS
                               para decidir el scope.

Un objetivo sin esquema ni puerto (p.ej. "api.ejemplo.com") tiene puerto y ruta
desconocidos: solo lo autoriza un patron sin restriccion de puerto ni de ruta.

Ninguna etapa de recon/escaneo debe tocar un objetivo que no pase por
Scope.is_allowed(). Los tests en tests/test_scope.py lo verifican.
"""
from __future__ import annotations

import functools
import ipaddress
import posixpath
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlparse

import yaml
from pydantic import BaseModel, Field, field_validator

from .config import RESOURCES, ROOT

_DEFAULT_PORTS = {"http": 80, "https": 443}
_PROGRAM_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
# Valores que se pasan como argumento a nuclei: sin espacios ni "-" inicial.
_NUCLEI_ARG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._/:*+-]{0,199}$")


class PhaseNotAllowed(Exception):
    """La politica del scope prohibe ejecutar esta fase."""


class ScopeRules(BaseModel):
    rate_limit_rps: int = 5
    allow_active_scan: bool = True
    allow_automated_tools: bool = True
    # Por defecto "*.ejemplo.com" NO incluye "ejemplo.com" (falla cerrado). Ponlo a
    # true solo si la politica del programa dice que el wildcard cubre el apex.
    wildcard_includes_apex: bool = False
    notes: str = ""


class NucleiPolicy(BaseModel):
    """Que plantillas de nuclei permite el programa.

    Si templates, template_ids y tags estan vacios, nuclei usa todas las
    plantillas instaladas (filtradas por severity y exclude_tags). Con un scope
    limitado por ruta, nuclei NO se ejecuta sin una allowlist explicita.
    """
    templates: list[str] = Field(default_factory=list)      # -t (rutas/dirs de plantillas)
    template_ids: list[str] = Field(default_factory=list)   # -id
    tags: list[str] = Field(default_factory=list)           # -tags
    exclude_tags: list[str] = Field(default_factory=lambda: [
        "dos", "fuzz", "intrusive", "bruteforce", "brute-force",
    ])                                                      # -etags
    severity: list[str] = Field(default_factory=lambda: ["low", "medium", "high", "critical"])
    # Interactsh envia datos a un servidor OAST de terceros: desactivado salvo que
    # el programa lo permita.
    allow_interactsh: bool = False

    @field_validator("templates", "template_ids", "tags", "exclude_tags", "severity")
    @classmethod
    def _safe_values(cls, v: list[str]) -> list[str]:
        clean = []
        for item in v or []:
            item = str(item).strip()
            if not _NUCLEI_ARG_RE.fullmatch(item) or ".." in item:
                raise ValueError(f"valor no valido para nuclei: {item!r}")
            clean.append(item)
        return clean

    @field_validator("severity")
    @classmethod
    def _known_severity(cls, v: list[str]) -> list[str]:
        allowed = {"info", "low", "medium", "high", "critical", "unknown"}
        bad = [s for s in v if s.lower() not in allowed]
        if bad:
            raise ValueError(f"severidad desconocida: {bad}")
        return [s.lower() for s in v]

    def is_allowlist(self) -> bool:
        return bool(self.templates or self.template_ids or self.tags)

    def args(self) -> list[str]:
        out: list[str] = []
        for t in self.templates:
            out += ["-t", t]
        if self.template_ids:
            out += ["-id", ",".join(self.template_ids)]
        if self.tags:
            out += ["-tags", ",".join(self.tags)]
        if self.exclude_tags:
            out += ["-etags", ",".join(self.exclude_tags)]
        if self.severity:
            out += ["-severity", ",".join(self.severity)]
        if not self.allow_interactsh:
            out.append("-no-interactsh")
        return out


# ------------------------------------------------------------------ patrones
@dataclass(frozen=True)
class Target:
    host: str
    port: int | None      # None = desconocido (objetivo sin esquema ni puerto)
    path: str             # "" = desconocida
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None


@dataclass(frozen=True)
class Pattern:
    raw: str
    host: str = ""                    # "" si es IP/CIDR
    wildcard: bool = False
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    port: int | None = None           # None = cualquier puerto
    path: str = ""                    # "" = cualquier ruta
    scheme: str = ""

    @property
    def host_wide(self) -> bool:
        """Cubre el host completo (sin limite de puerto ni ruta)."""
        return self.port is None and not self.path

    def describe(self) -> str:
        parts = []
        if self.port is not None:
            parts.append(f"puerto {self.port}")
        if self.path:
            parts.append(f"ruta {self.path}")
        return f"'{self.raw}'" + (f" ({', '.join(parts)})" if parts else "")


def _norm_path(path: str) -> str:
    path = unquote(path or "")
    if not path:
        return ""
    norm = posixpath.normpath("/" + path.lstrip("/"))
    return "/" if norm in ("/", "//") else norm.rstrip("/")


def _as_ip(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def parse_target(target: str) -> Target | None:
    target = (target or "").strip()
    if not target:
        return None
    has_scheme = "://" in target
    bare_ip = _as_ip(target) if not has_scheme else None
    if bare_ip is not None and bare_ip.version == 6:
        target = f"[{bare_ip}]"  # IPv6 sin corchetes: los ':' no son un puerto
    parsed = urlparse(target if has_scheme else "//" + target)
    try:
        host = (parsed.hostname or "").lower().rstrip(".")
        explicit_port = parsed.port
    except ValueError:  # puerto no numerico o fuera de rango
        return None
    if not host:
        return None
    scheme = parsed.scheme.lower() if has_scheme else ""
    port = explicit_port if explicit_port is not None else _DEFAULT_PORTS.get(scheme)
    path = _norm_path(parsed.path) if (has_scheme or parsed.path) else ""
    if has_scheme and not path:
        path = "/"
    return Target(host=host, port=port, path=path, ip=_as_ip(host))


@functools.lru_cache(maxsize=1024)
def parse_pattern(raw: str) -> Pattern:
    text = (raw or "").strip()
    if not text:
        raise ValueError("patron vacio")
    # IP o CIDR sin puerto
    try:
        net = ipaddress.ip_network(text, strict=False)
        return Pattern(raw=text, network=net)
    except ValueError:
        pass
    wildcard = False
    body = text
    if "://" not in body and body.startswith("*."):
        wildcard, body = True, body[2:]
    elif "://" in body:
        scheme_part, rest = body.split("://", 1)
        if rest.startswith("*."):
            wildcard, body = True, f"{scheme_part}://{rest[2:]}"
    t = parse_target(body)
    if t is None:
        raise ValueError(f"patron de scope no valido: {text!r}")
    if "*" in t.host:
        raise ValueError(f"solo se admite el wildcard al inicio ('*.dominio'): {text!r}")
    scheme = body.split("://", 1)[0].lower() if "://" in body else ""
    path = "" if t.path == "/" else t.path
    if t.ip is not None:
        if wildcard:
            raise ValueError(f"wildcard no aplicable a una IP: {text!r}")
        net = ipaddress.ip_network(t.ip)
        return Pattern(raw=text, network=net, port=t.port, path=path, scheme=scheme)
    return Pattern(raw=text, host=t.host, wildcard=wildcard, port=t.port, path=path, scheme=scheme)


def _host_matches(t: Target, p: Pattern, include_apex: bool) -> bool:
    if p.network is not None:
        return t.ip is not None and t.ip in p.network
    if p.wildcard:
        return t.host.endswith("." + p.host) or (include_apex and t.host == p.host)
    return t.host == p.host


def _matches(t: Target, p: Pattern, include_apex: bool) -> bool:
    if not _host_matches(t, p, include_apex):
        return False
    if p.port is not None and t.port != p.port:
        return False
    if p.path:
        if not t.path:
            return False
        if t.path != p.path and not t.path.startswith(p.path + "/"):
            return False
    return True


# --------------------------------------------------------------------- scope
class Scope(BaseModel):
    program: str = "unnamed"
    platform: str = "privado"
    policy_url: str = ""
    in_scope: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    rules: ScopeRules = Field(default_factory=ScopeRules)
    nuclei: NucleiPolicy = Field(default_factory=NucleiPolicy)
    # Cabeceras que exige el programa en TODO el trafico (p.ej. X-Bug-Bounty: usuario).
    # Se pasan a httpx, nuclei y dalfox.
    request_headers: dict[str, str] = Field(default_factory=dict)

    @field_validator("in_scope", "out_of_scope")
    @classmethod
    def _check_patterns(cls, v: list[str]) -> list[str]:
        out = []
        for raw in v or []:
            raw = str(raw).strip()
            parse_pattern(raw)  # lanza ValueError con mensaje claro
            out.append(raw)
        return out

    @field_validator("request_headers")
    @classmethod
    def _check_headers(cls, v: dict[str, str]) -> dict[str, str]:
        clean = {}
        for name, value in (v or {}).items():
            name, value = str(name).strip(), str(value).strip()
            if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", name):
                raise ValueError(f"nombre de cabecera invalido: {name!r}")
            if any(c in value for c in "\r\n\0") or len(value) > 512:
                raise ValueError(f"valor de cabecera invalido para {name}")
            clean[name] = value
        return clean

    # ---- patrones ----
    def _in(self) -> list[Pattern]:
        return [parse_pattern(p) for p in self.in_scope]

    def _out(self) -> list[Pattern]:
        return [parse_pattern(p) for p in self.out_of_scope]

    @property
    def _apex(self) -> bool:
        return self.rules.wildcard_includes_apex

    def has_restricted_patterns(self) -> bool:
        """True si algun patron in_scope limita puerto o ruta."""
        return any(not p.host_wide for p in self._in())

    def has_path_patterns(self) -> bool:
        return any(p.path for p in self._in())

    # ---- decision ----
    def is_allowed(self, target: str) -> bool:
        t = parse_target(target)
        if t is None:
            return False
        if any(_matches(t, p, self._apex) for p in self._out()):
            return False
        return any(_matches(t, p, self._apex) for p in self._in())

    def reason(self, target: str) -> str:
        t = parse_target(target)
        if t is None:
            return "objetivo invalido (sin host)"
        for p in self._out():
            if _matches(t, p, self._apex):
                return f"'{t.host}' coincide con out_of_scope {p.describe()}"
        for p in self._in():
            if _matches(t, p, self._apex):
                return f"'{t.host}' coincide con in_scope {p.describe()}"
        hosts = [p for p in self._in() if _host_matches(t, p, self._apex)]
        if hosts:
            limits = ", ".join(p.describe() for p in hosts)
            return f"el host '{t.host}' solo esta autorizado con limites: {limits}"
        if t.ip is None and any(p.network is not None for p in self._in()):
            return (f"'{t.host}' no coincide con ningun patron in_scope "
                    "(los rangos IP/CIDR no se aplican a hostnames: no se resuelve DNS)")
        if (any(p.wildcard and p.host == t.host for p in self._in()) and not self._apex):
            return (f"'{t.host}' es el apex de un wildcard y wildcard_includes_apex=false; "
                    "anadelo explicitamente a in_scope si la politica lo cubre")
        return f"'{t.host}' no coincide con ningun patron in_scope"

    def filter_allowed(self, targets: list[str]) -> tuple[list[str], list[str]]:
        """Devuelve (permitidos, rechazados)."""
        allowed, rejected = [], []
        for t in targets:
            (allowed if self.is_allowed(t) else rejected).append(t)
        return allowed, rejected

    # ---- apoyo al recon ----
    def seed_domains(self) -> list[str]:
        """Dominios base para la enumeracion pasiva (no incluye IP/CIDR)."""
        return sorted({p.host for p in self._in() if p.host})

    def seed_ips(self) -> list[str]:
        """IPs sueltas del scope (los rangos CIDR no se expanden)."""
        ips = set()
        for p in self._in():
            if p.network is not None and p.network.num_addresses == 1:
                ips.add(str(p.network.network_address))
        return sorted(ips)

    def host_candidate(self, host: str) -> bool:
        """El host casa con algun patron in_scope (ignorando puerto/ruta) y no lo
        excluye un patron out_of_scope que cubra el host completo."""
        t = parse_target(host)
        if t is None:
            return False
        t = Target(host=t.host, port=None, path="", ip=t.ip)
        if any(p.host_wide and _host_matches(t, p, self._apex) for p in self._out()):
            return False
        return any(_host_matches(t, p, self._apex) for p in self._in())

    def probe_targets(self, host: str) -> list[str]:
        """Entradas para el sondeo HTTP de un host, segun los patrones que lo cubren:
        el host tal cual, host:puerto o la URL con la ruta autorizada."""
        t = parse_target(host)
        if t is None:
            return []
        bare = Target(host=t.host, port=None, path="", ip=t.ip)
        h = f"[{t.host}]" if t.ip is not None and t.ip.version == 6 else t.host
        out: list[str] = []
        for p in self._in():
            if not _host_matches(bare, p, self._apex):
                continue
            if p.host_wide:
                item = h
            elif p.path:
                scheme = p.scheme or "https"
                default = _DEFAULT_PORTS.get(scheme)
                port = f":{p.port}" if p.port is not None and p.port != default else ""
                item = f"{scheme}://{h}{port}{p.path}/"
            else:
                item = f"{p.scheme}://{h}:{p.port}" if p.scheme else f"{h}:{p.port}"
            if item not in out:
                out.append(item)
        return out

    def check_phase(self, phase: str) -> None:
        """Bloqueo duro segun las reglas (no se salta con --yes).

        - allow_automated_tools=false -> ninguna fase con herramientas (recon, scan).
        - allow_active_scan=false     -> no hay escaneo (nuclei/dalfox); el recon
          queda en modo pasivo (subfinder sin sondeo httpx).
        """
        if not self.rules.allow_automated_tools:
            raise PhaseNotAllowed(
                f"'{phase}' bloqueado: el scope tiene allow_automated_tools=false. "
                "Trabaja manualmente segun la politica del programa."
            )
        if phase == "scan" and not self.rules.allow_active_scan:
            raise PhaseNotAllowed(
                "'scan' bloqueado: el scope tiene allow_active_scan=false. "
                "Solo puedes hacer recon pasivo y pruebas manuales permitidas."
            )

    def effective_rate_limit(self, global_cap: int) -> int:
        return max(1, min(self.rules.rate_limit_rps, global_cap))


# --------------------------------------------------------------- programas
def programs_dir() -> Path:
    return ROOT / "programs"


def valid_program_name(name: str) -> bool:
    return bool(_PROGRAM_RE.fullmatch(name or ""))


def program_scope_path(name: str) -> Path:
    if not valid_program_name(name):
        raise ValueError(
            f"nombre de programa no valido: {name!r} (minusculas, digitos, '.', '_' o '-'; max 64)"
        )
    return programs_dir() / name / "scope.yaml"


def list_programs() -> list[str]:
    d = programs_dir()
    if not d.is_dir():
        return []
    return sorted(p.name for p in d.iterdir()
                  if p.is_dir() and valid_program_name(p.name) and (p / "scope.yaml").exists())


def load_scope(path: str | Path | None = None, program: str | None = None) -> Scope:
    """Carga el scope.

    - program="x" -> programs/x/scope.yaml (el campo program debe ser "x" o faltar).
    - path        -> ese fichero.
    - nada        -> config/scope.yaml, o el ejemplo si no existe.
    """
    if program:
        path = program_scope_path(program)
        if not path.exists():
            raise FileNotFoundError(
                f"No existe {path}. Crealo con: bbhunter init --program {program}"
            )
    elif path is None:
        path = ROOT / "config" / "scope.yaml"
        if not path.exists():
            path = RESOURCES / "config" / "scope.example.yaml"
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if program:
        declared = data.get("program")
        if declared in (None, "", "unnamed", "ejemplo-programa"):
            data["program"] = program
        elif declared != program:
            raise ValueError(
                f"{path}: program='{declared}' no coincide con el directorio '{program}'. "
                "Usa el mismo nombre para que BD, informes y auditoria no se mezclen."
            )
    return Scope(**data)
