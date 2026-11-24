# 🛡️ BBHunter

Asistente **semi-automático** de bug bounty para **Kali Linux**. A partir del *scope*
de un programa autorizado: enumera activos, escanea vulnerabilidades, las clasifica por
severidad (CVSS v3.1 + tier VRT P1–P5), redacta la explicación / pasos de reproducción /
impacto / remediación (con **Claude**) y genera **informes profesionales** listos para que
**tú los revises, valides y envíes**.

> ## ⚠️ Lee esto antes de nada
> - **Solo pruebas autorizadas.** Escanear sistemas sin permiso explícito es ilegal. Usa
>   BBHunter únicamente dentro del scope de un programa de bug bounty o con autorización escrita.
> - **No envía reportes automáticamente, y es a propósito.** HackerOne, Bugcrowd y YesWeHack
>   **prohíben el escaneo no autorizado y banean el envío automático de reportes sin validar**
>   ("beg bounty"/spam). El flujo correcto —y el único que cobra— incluye **validación humana**.
> - **Muchos programas prohíben herramientas automáticas.** Confírmalo en la política del
>   programa (`allow_automated_tools` en el scope) antes de lanzar nada.

---

## Instalación (Kali Linux)

```bash
bash scripts/install_tools.sh      # instala subfinder, httpx, naabu, nuclei, dalfox + venv Python
source .venv/bin/activate
bbhunter init                      # crea config/scope.yaml y config/settings.yaml
export ANTHROPIC_API_KEY=sk-ant-...   # para la redacción con Claude
```

Edita:
- **`config/scope.yaml`** → el scope REAL del programa (in_scope / out_of_scope / reglas).
- **`config/settings.yaml`** → modelo de Claude, rate limits, rutas de binarios.

## Uso

```bash
bbhunter scope-check https://www.ejemplo.com   # ¿está en scope?
bbhunter run                                   # pipeline completo (recon→scan→enrich→report)
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

1. `bbhunter run` sobre un scope autorizado.
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

Pon `dry_run: true` en `config/settings.yaml` o despliega un laboratorio **legal**
(OWASP Juice Shop / DVWA) en local y apunta el scope a `localhost`. En `dry_run` el
pipeline genera hallazgos de ejemplo para validar informes y dashboard sin tocar nada.

```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop   # laboratorio legal
```

## Tests

```bash
pip install -e ".[dev]"
pytest -q
```

## Estructura

```
bbhunter/    paquete Python (cli, scope, recon, scan, enrich, llm, report, dashboard)
config/      scope.yaml y settings.yaml (copias de los *.example.yaml)
knowledge/   vrt_mapping.yaml (CVSS↔tier) y vuln_kb.yaml (clases de vuln)
templates/   plantillas de informe (Markdown/HTML)
scripts/     install_tools.sh, run_pipeline.sh
tests/       tests (scope, dedup, report)
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
