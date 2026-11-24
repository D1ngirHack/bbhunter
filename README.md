# 🛡️ BBHunter

**Guía detallada:** [abrir el PDF](GUIA_BBHunter.pdf) ·
[fuente editable](docs/GUIA_BBHunter.md) ·
[plantilla de informe](docs/plantilla_informe.md).

La guía incluye instalación en Kali/WSL, configuración de scope frente a URL,
simulación, laboratorio local, enumeración, validación con Burp/curl, uso acotado
de herramientas, informe de ejemplo y revisión de los 35 ficheros originales.

**Scope:** patrones por host, `*.dominio`, puerto (`app.ejemplo.com:8443`), ruta
(`https://app.ejemplo.com/api/`) e IP/CIDR (solo objetivos escritos como IP; no se resuelve DNS).
El wildcard **no** incluye el dominio raíz salvo `rules.wildcard_includes_apex: true`.
`bbhunter scope-check URL` dice qué límite falla y sale con código 1 si está fuera.

**Bloqueos de política:** `allow_automated_tools: false` bloquea `recon`, `scan` y
`run`; `allow_active_scan: false` bloquea `scan`/`run` y deja `recon` en modo pasivo
(sin httpx). Ninguno se salta con `--yes`. `dry_run` sigue disponible.

**Uso responsable en programas reales:**
- **Cabeceras del programa:** `request_headers` en `scope.yaml` (p. ej. `X-Bug-Bounty: usuario`)
  se envían con httpx, nuclei y dalfox. **Proxy** opcional (`proxy` en `settings.yaml`, p. ej. Burp).
- **Auditoría:** cada ejecución de herramienta queda en `data/audit.jsonl`
  (`bbhunter audit`, `bbhunter audit --failed`). Si una herramienta falla verás
  **FALLO** / **RESULTADO INCOMPLETO**, nunca un "0 hallazgos" engañoso.
- **Plantillas de Nuclei por programa:** bloque `nuclei:` del scope (allowlist `templates`/`template_ids`/`tags`,
  `exclude_tags`, severidades). Interactsh desactivado salvo `allow_interactsh: true`. Con un scope
  limitado por ruta, Nuclei no se ejecuta sin allowlist.
- **Un directorio por programa:** `bbhunter init --program acme` → `programs/acme/scope.yaml`;
  después `bbhunter -p acme <comando>` (o `BBHUNTER_PROGRAM=acme`). `bbhunter programs` los lista.
- **Panel protegido:** solo Host local (contra DNS rebinding), token CSRF y mismo origen en cada acción,
  CSP y acciones limitadas al programa activo.
- **Secretos:** la evidencia se guarda con contraseñas, claves y tokens enmascarados
  (`redact_evidence`) y a Claude solo llega enmascarada, o nada con `llm_evidence: "none"`.

Empieza con `dry_run: true`, `llm_enabled: false` y una base separada para la demo.

Asistente **semi-automático** de bug bounty para **Kali Linux**. A partir del *scope*
de un programa autorizado: enumera activos, escanea vulnerabilidades, las clasifica por
severidad (CVSS v3.1 + tier VRT P1–P5), redacta la explicación / pasos de reproducción /
impacto / remediación (con **Claude**) y genera **informes profesionales** listos para que
**tú los revises, valides y envíes**.

> ## ⚠️ Lee esto antes de nada
> - **Solo pruebas autorizadas.** Escanear sistemas sin permiso explícito es ilegal. Usa
>   BBHunter únicamente dentro del scope de un programa de bug bounty o con autorización escrita.
> - **El envío es manual.** Reproduce y revisa cada caso antes de enviarlo por el
>   canal oficial del programa. La aceptación y cualquier recompensa dependen de
>   sus condiciones y de la evaluación del equipo.
> - **Comprueba qué automatización permite el programa.** La configuración local
>   no sustituye su política: refleja sus reglas en `allow_automated_tools` y
>   `allow_active_scan`, que BBHunter aplica como bloqueo.

---

## Instalación (Kali Linux)

```bash
bash scripts/install_tools.sh      # instala subfinder, httpx, naabu, nuclei, dalfox + venv Python
source .venv/bin/activate
bbhunter init                      # crea config/scope.yaml y config/settings.yaml
bbhunter init --program acme       # o un scope por programa: programs/acme/scope.yaml
export ANTHROPIC_API_KEY=sk-ant-...   # para la redacción con Claude
```

Edita:
- **`config/scope.yaml`** (o `programs/NOMBRE/scope.yaml`) → el scope REAL del programa
  (in_scope / out_of_scope / reglas / plantillas de nuclei).
- **`config/settings.yaml`** → modelo de Claude, rate limits, rutas de binarios.

## Uso

```bash
bbhunter scope-check https://www.ejemplo.com   # ¿está en scope?
bbhunter run                                   # primero en simulación; revisa límites antes de uso real
bbhunter dashboard                             # panel web local en http://127.0.0.1:8000
```

O por fases:

```bash
bbhunter recon          # subdominios + hosts vivos (subfinder, httpx)
bbhunter scan           # nuclei + dalfox (pide confirmación de autorización)
bbhunter enrich         # redacta el contenido de los informes con Claude
bbhunter list           # lista los hallazgos
bbhunter report --pdf   # genera informes Markdown/HTML/PDF en reports/
```

### Triaje (dashboard)
El panel web (solo localhost) permite revisar cada hallazgo, marcar su estado
(`new → validated / false_positive / duplicate → ready → reported`) y generar el informe.
**El envío a la plataforma lo haces tú manualmente.**

### Referencias: informes divulgados (HackerOne) y writeups (Medium)
Material de **consulta**: estos comandos solo leen fuentes públicas y nunca tocan ningún objetivo.

```bash
bbhunter refs sync                    # descarga/actualiza ambas fuentes (--source hackerone|medium)
bbhunter refs stats                   # cuántas hay y cuándo se sincronizó
bbhunter refs search "ssrf"           # búsqueda libre (--source, --limit)
bbhunter refs finding 3               # informes/writeups parecidos al hallazgo #3 + rango de bounties
```

- **HackerOne:** dataset de ~10.000 informes divulgados de
  [codebygk/hackerone-bug-bounty-reports](https://github.com/codebygk/hackerone-bug-bounty-reports).
  Solo incluye metadatos (título, programa, tipo, severidad, bounty, enlace); el texto completo
  se lee en hackerone.com. El repo no declara licencia y no se actualiza desde 10/2024, así que
  BBHunter **no lo incluye**: lo descarga a `data/` (ignorado por git).
- **Medium:** feeds RSS por etiqueta (`references.medium_tags` en `settings.yaml`). El RSS solo
  trae las ~10 publicaciones más recientes de cada etiqueta, así que conviene sincronizar a menudo
  para ir acumulando. No se hace scraping de artículos.
- En el **dashboard**, cada hallazgo muestra sus informes y writeups similares.
- En `bbhunter enrich`, los títulos y bounties de informes similares se pasan a Claude **solo para
  calibrar el impacto**, marcados como datos de terceros (`references.in_llm_prompt: false` lo desactiva).

## Flujo de trabajo recomendado

1. Revisa política y límites de esta versión; practica primero con la simulación de la guía.
2. En el dashboard, **valida** cada hallazgo (descarta falsos positivos: es lo que más banea).
3. Reproduce manualmente el PoC y añade capturas de pantalla al informe.
4. Marca el hallazgo como `ready`, exporta el informe y **envíalo tú** desde la plataforma.

## Severidad y tiers

| Tier | Severidad | Ejemplos | Pago orientativo (USD) |
|------|-----------|----------|------------------------|
| P1 | Critical | RCE, SQLi con exfiltración, auth bypass | 2.000 – 20.000+ |
| P2 | High | XSS almacenado auth, IDOR sensible, SSRF ciego | 750 – 5.000 |
| P3 | Medium | Reflected XSS, CSRF con impacto | 150 – 1.000 |
| P4 | Low | Fugas menores, configs débiles | 50 – 250 |
| P5 | Info | Buenas prácticas, sin impacto | normalmente 0 |

## Probar sin objetivo real (modo simulación)

Pon `dry_run: true` y `llm_enabled: false` en `config/settings.yaml`, y elige una
base/directorio de salida exclusivos para la demo. `dry_run` evita el recon y
escaneo real, pero no deshabilita por sí solo la API de redacción ni `refs sync`.
No envíes sus hallazgos de ejemplo. El capítulo 07 de la guía contiene la
configuración completa y el 09 un laboratorio local con Burp/curl.

```bash
docker run --rm -p 127.0.0.1:3000:3000 bkimminich/juice-shop
# Abre http://127.0.0.1:3000 con navegador/curl.
# El recon del pipeline no selecciona automáticamente ese puerto.
```

## Tests

```bash
pip install -e ".[dev]"
ruff check .
pytest -q
```

El CI (`.github/workflows/ci.yml`) ejecuta ruff y pytest en Python 3.11–3.13 y prueba el
wheel instalado fuera del repositorio. Los datos de trabajo (`config/`, `programs/`, `data/`,
`reports/`) se buscan en `BBHUNTER_HOME`, en el repo si trabajas desde un checkout, o en el
directorio actual.

## Estructura

```
bbhunter/            paquete Python (cli, scope, recon, scan, enrich, llm, report, dashboard)
bbhunter/resources/  config/*.example.yaml, knowledge/ (CVSS↔tier, clases) y templates/ (informes)
config/              scope.yaml y settings.yaml locales (gitignored)
programs/NOMBRE/     scope.yaml (y settings.yaml opcional) por programa (gitignored)
scripts/             install_tools.sh, run_pipeline.sh, build_guide.py
tests/               tests (scope, gates, esenciales, importantes, dedup, report, refs)
reports/     informes generados (gitignored)
data/        base de datos SQLite (gitignored)
```

## Alcance del MVP

Clases de vulnerabilidad curadas: **exposiciones/malas configuraciones** y **XSS reflejado**.
El resto de hallazgos de nuclei se listan y puntúan, pero su redacción es más genérica.

## Limitaciones / fuera de alcance

Sin envío automático a plataformas · sin escaneo masivo/distribuido · sin explotación
agresiva más allá del PoC de validación. Por diseño: la responsabilidad legal y la
validación son tuyas.

## Regenerar la guía

```bash
python -m pip install reportlab
python scripts/build_guide.py
```

Genera `output/pdf/GUIA_BBHunter.pdf` y actualiza la copia de la raíz. No ejecuta
escáneres. La exportación de informes de hallazgos con `bbhunter report --pdf`
es independiente y usa WeasyPrint.
