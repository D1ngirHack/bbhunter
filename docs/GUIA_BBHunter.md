# 01. Cómo utilizar esta guía

El objetivo es que puedas pasar de una instalación vacía a una investigación documentada y a un informe que el equipo del programa pueda reproducir. Cada fase explica qué introducir, qué comando ejecutar, qué resultado revisar y cuándo avanzar. La guía describe el código que existe en este repositorio, incluidas sus limitaciones.

**Respuesta directa a «¿le doy un scope o una URL?»** BBHunter lee el alcance desde `config/scope.yaml`. No descarga la política ni extrae automáticamente los activos de HackerOne o Bugcrowd. `policy_url` es una referencia informativa. `bbhunter run https://...` no es una forma admitida de ejecutar el programa. Una URL se admite en `bbhunter scope-check URL`, que comprueba host, puerto y ruta según los patrones del scope. Con `bbhunter -p NOMBRE ...` el alcance se lee de `programs/NOMBRE/scope.yaml`.

## Elige tu ruta

| Situación | Ruta de trabajo |
|---|---|
| Primera vez o aprendizaje | Instala, configura la simulación del capítulo 07 y practica el laboratorio del 09. |
| Un host completo, automatización y escaneo permitidos | Prepara el alcance, revisa las limitaciones del 02 y trabaja por fases. |
| Solo una ruta, un puerto, una app autenticada o cabeceras obligatorias | Usa herramientas manuales con límites explícitos. Redacta con la plantilla del 23. |
| El programa prohíbe herramientas automáticas | Navegación y comprobaciones manuales permitidas por su política. No ejecutes recon, scan ni run. |
| Ya tienes un hallazgo | Empieza por los capítulos 18 a 24: validación, evidencia, severidad, informe y envío. |

## Qué debes tener al terminar

1. Una copia fechada de la política y una lista explícita de activos permitidos y excluidos.
2. Un inventario de hosts y funciones revisadas, con URLs y procedencia.
3. Una hipótesis comprobada con cuentas propias y una prueba mínima repetible.
4. Petición, respuesta, resultado esperado, resultado observado e impacto demostrado.
5. Un informe revisado, sus adjuntos privados y el identificador que devuelve la plataforma al enviarlo.

> Los dominios `example.test` y sus subdominios son ejemplos reservados: no son objetivos reales. Sustitúyelos únicamente por activos que hayas verificado en la política del programa. Los comandos del laboratorio usan `127.0.0.1`.

Los bloques `bash` se ejecutan dentro de Kali, desde la raíz del repositorio y con el entorno virtual activo. Los bloques PowerShell están identificados. Las salidas ilustrativas se etiquetan como tales. No ejecutes todos los bloques seguidos: cada fase tiene una condición para continuar.

# 02. Qué hace realmente esta versión

BBHunter 0.1.0 es un asistente de reconocimiento web, almacenamiento de candidatos y generación de borradores. Usa `subfinder` para descubrimiento pasivo, `httpx` para sondeo HTTP, Nuclei para plantillas y Dalfox para posibles XSS en URLs con parámetros. SQLite conserva activos y hallazgos. El panel permite revisar y cambiar estados. La redacción puede usar plantillas locales o la API de Anthropic.

## Limitaciones que condicionan el uso

| Comprobación del código | Consecuencia práctica |
|---|---|
| El scope compara host, puerto (fijado por el esquema si el patrón es una URL) y ruta. Las IP/CIDR solo casan con objetivos escritos como IP. | No resuelve DNS ni controla métodos, cuentas o tipos de prueba. Un hostname nunca queda autorizado por un rango CIDR. |
| `*.dominio` no incluye `dominio` salvo `rules.wildcard_includes_apex: true`. | Si la política cubre el dominio raíz, añádelo a `in_scope` o activa esa regla. |
| `allow_automated_tools: false` bloquea `recon`, `scan` y `run` (código de salida 2), también con `--yes`. | Es un bloqueo técnico de BBHunter, no de otras herramientas: no lances manualmente comandos automatizados que la política prohíba. |
| `allow_active_scan: false` bloquea `scan` y `run` (Nuclei y Dalfox) y deja `recon` en modo pasivo: subfinder sin sondeo httpx. | Los subdominios se guardan con fuente `pasivo-sin-sondeo`: son candidatos sin verificar, no hosts vivos. |
| Nuclei recibe la política del programa (bloque `nuclei:` del scope): allowlist (`templates`, `template_ids`, `tags`), `exclude_tags`, severidades e `-no-interactsh` salvo `allow_interactsh: true`. | Sin allowlist usa todas las plantillas instaladas. Si el scope limita rutas, `scan` omite Nuclei hasta que definas una allowlist, porque muchas plantillas atacan la raíz del host. |
| No hay crawler ni importador de endpoints en la CLI. | Las rutas de la aplicación y las APIs requieren mapeo manual. Dalfox puede no tener candidatos. |
| Sin httpx se crean URLs HTTPS supuestas. | «Host vivo» en la salida no demuestra una respuesta real. Revisa la fuente del activo. |
| La severidad se asigna por clase con un vector predeterminado. | Recalcula según evidencia; el resultado de BBHunter no es la severidad definitiva. |

## Otras diferencias con una herramienta completa

- Naabu se instala y aparece en la configuración, pero el pipeline no lo ejecuta.
- Sí hay cabeceras de identificación por programa (`request_headers` en el scope) y proxy opcional (`proxy` en settings) para httpx, Nuclei y Dalfox. No hay cookies/sesiones para los escáneres del pipeline.
- Cada ejecución de herramienta queda en `data/audit.jsonl` (`bbhunter audit`) y los fallos se muestran como «FALLO» y «RESULTADO INCOMPLETO» en vez de pasar por cero hallazgos.
- Cada programa puede vivir en `programs/NOMBRE/` (`bbhunter init --program NOMBRE`, después `bbhunter -p NOMBRE ...`). El panel exige Host local, token CSRF y mismo origen en sus acciones, y solo muestra hallazgos del programa activo.
- El panel no permite editar los textos ni adjuntar capturas. Debes completar el informe en un editor y adjuntar evidencia en la plataforma.
- `report` puede generar documentos de hallazgos `new`; exportar no equivale a validar.
- El pipeline no descubre vulnerabilidades de autorización, autenticación o lógica de negocio de manera sistemática.
- La deduplicación local no permite saber si otra persona ya informó al programa.

**Decisión operativa:** empieza con simulación. Para un programa real, utiliza las fases manuales y herramientas con parámetros explícitos cuando necesites restricciones que el pipeline no representa. No uses `run` como primer paso sobre un programa.

El apéndice 28 relaciona estas conclusiones con todos los ficheros de la aplicación. El capítulo 29 explica lo que se comprobó, lo que ya se corrigió en el código y las mejoras pendientes.

# 03. Preparar Kali desde Windows o Linux

El instalador incluido está escrito para Kali/Debian y usa Bash, `apt`, Go y un entorno virtual Linux. Una `.venv` creada en Windows no se reutiliza dentro de Linux. La revisión de este repositorio se realizó en Windows; eso no constituye una prueba de instalación del conjunto de herramientas en Kali.

## Opción A: Kali en WSL

En PowerShell, usa el procedimiento oficial de Kali [S01]. La instalación puede pedir elevación y reinicio. Después de crear el usuario Linux, el trabajo del proyecto se hace en la terminal de Kali.

```powershell
wsl --list --online
wsl --install --distribution kali-linux
wsl --list --verbose
wsl --distribution kali-linux
```

Para trabajar con Burp y navegador, también puedes usar una máquina virtual Kali con escritorio. Si usas WSL, el navegador integrado de Burp debe ejecutarse en un entorno gráfico disponible; no es un requisito para la simulación de BBHunter.

## Opción B: Kali ya instalado

Abre una terminal como usuario habitual. Comprueba el entorno e instala utilidades básicas:

```bash
uname -a
python3 --version
sudo apt update
sudo apt install -y git curl ca-certificates rsync python3-venv \
  python3-pip golang-go build-essential libpcap-dev
```

Se necesita Python 3.11 o superior. Go debe satisfacer la versión requerida por cada herramienta; si `go install` indica que es demasiado antiguo, consulta las instrucciones oficiales de Go [S02]. No presupongas que el paquete disponible en tu distribución tiene la versión requerida.

## Llevar el repositorio a Kali

Si dispones del repositorio remoto y de acceso, clónalo dentro del sistema de ficheros Linux:

```bash
mkdir -p "$HOME/proyectos"
cd "$HOME/proyectos"
git clone https://github.com/D1ngirHack/bbhunter.git
cd bbhunter
```

Si el repositorio requiere autenticación, usa el acceso HTTPS/SSH configurado en tu cuenta. Evita escribir tokens en la URL, el historial o un almacén de credenciales en texto plano. La privacidad o disponibilidad del remoto no se deduce del PDF.

Como alternativa, para copiar esta carpeta desde Windows a una carpeta nueva en WSL:

```bash
mkdir -p "$HOME/proyectos/bbhunter"
rsync -a --exclude='.venv/' --exclude='.git/' \
  --exclude='data/' --exclude='reports/' \
  /mnt/c/Users/Jonay/Desktop/BugBounty/ "$HOME/proyectos/bbhunter/"
cd "$HOME/proyectos/bbhunter"
```

Esta copia conserva código y documentación, sin trasladar la base ni los informes anteriores. Si ya tienes configuraciones locales en origen, revisa sus rutas y usa una copia nueva para el laboratorio. **Resultado esperado:** la carpeta contiene `pyproject.toml`, `bbhunter/`, `config/` y `scripts/`.

# 04. Instalar y verificar BBHunter

## Instalación incluida en el proyecto

Desde la raíz del proyecto, revisa el instalador antes de ejecutarlo. Instala dependencias del sistema, las cinco herramientas Go, las plantillas de Nuclei y BBHunter con el extra PDF. Descarga software; no realiza un escaneo de objetivos.

```bash
less scripts/install_tools.sh
bash scripts/install_tools.sh
source .venv/bin/activate
export PATH="$HOME/go/bin:$PATH"
bbhunter --help
```

El `PATH` del script termina al salir del proceso Bash. Por eso hay que exportarlo en tu propia terminal. Para persistirlo, añade `export PATH="$HOME/go/bin:$PATH"` a `~/.bashrc` o al fichero de inicio de tu shell. El uso de `@latest` no fija versiones: registra cuáles quedan instaladas.

Si solo quieres practicar el flujo simulado sin herramientas externas ni PDF de hallazgos:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
bbhunter --help
python -m pytest -q
```

Esta ruta sí instala el paquete y sus dependencias Python, pero no instala Nuclei, httpx ni las otras herramientas Go. La guía PDF que estás leyendo se genera con ReportLab; los PDFs de hallazgos de `bbhunter report --pdf` usan WeasyPrint. Son dos procesos diferentes.

## Comprobaciones antes de tocar un objetivo

```bash
python --version
go version
command -v bbhunter subfinder httpx naabu nuclei dalfox
type -a httpx
subfinder -version
httpx -version
nuclei -version
dalfox version
bbhunter scan --help
bbhunter report --help
```

`httpx` debe ser el binario de ProjectDiscovery, no el cliente Python que comparte nombre. Si hay conflicto, configura su ruta absoluta, por ejemplo `tools.httpx: "/home/TU_USUARIO/go/bin/httpx"`. Sustituye el usuario real; YAML no expande `~` ni `$HOME` para estas rutas.

**Dalfox:** esta integración utiliza la interfaz Go v2 (`dalfox url`). La versión v3 tiene una interfaz distinta (`dalfox scan`) [S06, S07]. Comprueba la ayuda instalada. Si necesitas v2 para esta versión del proyecto, instala una release v2 mantenida y registra su número; no sustituyas silenciosamente por v3.

```bash
dalfox url --help
go install github.com/hahwul/dalfox/v2@v2.11.0
dalfox version
```

El comando con `v2.11.0` reproduce la interfaz consultada para esta guía, no promete que sea la versión preferida en el futuro. Antes de fijarla para trabajo real, comprueba los avisos y mantenimiento del proyecto. No necesitas Dalfox para seguir la validación manual de XSS.

**Para continuar:** `bbhunter --help` funciona, identificas los binarios correctos y sabes cuáles no has instalado. Los errores de instalación no deben interpretarse como «no hay vulnerabilidades».

# 05. Seleccionar programa y registrar sus reglas

Un programa público ofrece condiciones públicas de participación; el alcance sigue delimitando qué activos y pruebas permite. Abre su página oficial desde la plataforma y contrasta que el dominio de destino es el correcto. La presencia de una empresa en una plataforma no autoriza a probar todas sus marcas, proveedores o direcciones IP.

## Ficha de trabajo antes de ejecutar comandos

Crea una nota `data/casos/PROGRAMA/politica.md` con estos datos, completándolos desde la política vigente:

| Dato | Qué anotar |
|---|---|
| Programa, plataforma y URL | Identificador exacto y página oficial de la política. |
| Fecha de revisión | Momento de lectura y cambios conocidos. Guarda una copia o captura privada. |
| Activos autorizados | Hosts exactos, wildcards, apps, URLs o rangos que aparecen explícitamente. |
| Exclusiones | Hosts, rutas, servicios de terceros y clases de vulnerabilidad excluidas. |
| Métodos permitidos | Escaneo, automatización, OAST, crawling, fuzzing y pruebas autenticadas. |
| Límites | Peticiones por segundo, concurrencia, ventanas horarias y cabeceras identificadoras. |
| Cuentas y datos | Cuentas de prueba permitidas, dominios de correo, prohibiciones de datos reales. |
| Recompensa y canal | Activos elegibles para bounty, tabla propia del programa, formulario oficial. |
| Confidencialidad | Condiciones de divulgación y uso de servicios externos/IA. |

Si no existe un límite publicado, elige una tasa pequeña para las pruebas permitidas y consulta las dudas por el canal previsto. Una cifra elegida por ti no concede permiso de escaneo. Si una técnica está prohibida, omite esa técnica.

## Criterio para empezar

Para una primera investigación, elige una función comprensible y un host que puedas probar con dos cuentas propias. Por ejemplo, búsqueda, perfil o documentos de prueba. La familiaridad con el flujo funcional ayuda a distinguir el comportamiento previsto de un fallo de seguridad.

No confundas un VDP con un programa con recompensas: ambos pueden recibir vulnerabilidades, pero la elegibilidad para pago depende de las condiciones publicadas. Comprueba también que el activo concreto está marcado como elegible, si la plataforma hace esa distinción.

**Resultado de esta fase:** puedes señalar la línea de la política que autoriza el activo y el tipo de prueba. Todavía no has lanzado reconocimiento activo.

# 06. Traducir scope y URL a la configuración

## Crear los ficheros locales

```bash
bbhunter init
nano config/scope.yaml
nano config/settings.yaml
```

`init` copia los ejemplos (empaquetados en `bbhunter/resources/config/`) y no sobrescribe ficheros existentes. Las rutas `config/`, `programs/`, `data/` y `reports/` se resuelven respecto de `BBHUNTER_HOME` si la defines; si no, respecto del repositorio cuando trabajas desde un checkout, y del directorio actual en una instalación normal. Si falta la configuración local se usan los ejemplos; por eso debes crearla y revisarla antes de operar.

Para trabajar con varios programas sin mezclar alcances, crea uno por directorio:

```bash
bbhunter init --program acme      # crea programs/acme/scope.yaml
nano programs/acme/scope.yaml
bbhunter programs                 # lista programas, plataforma y hallazgos
bbhunter -p acme scope-check https://app.example.test/
```

Con `-p acme` (o `BBHUNTER_PROGRAM=acme`) todos los comandos usan ese scope, y `programs/acme/settings.yaml` si existe. El campo `program` del YAML debe coincidir con el nombre del directorio; si no, BBHunter se niega a cargarlo para que base, informes y auditoría no se mezclen. `programs/` está ignorado por Git.

## Caso A: solo está autorizado un host completo

Ejemplo didáctico. Sustituye nombre, política y host por los autorizados. Los false iniciales recuerdan que todavía no has habilitado pruebas activas; no son una barrera suficiente en este código.

```yaml
program: "programa-web"
platform: "hackerone"
policy_url: "https://hackerone.com/PROGRAMA_REAL"
in_scope:
  - "app.example.test"
out_of_scope: []
rules:
  rate_limit_rps: 1
  allow_active_scan: false
  allow_automated_tools: false
  notes: "Completar restricciones desde la politica real."
```

Un host sin esquema autoriza cualquier puerto y ruta de ese host. Si la política fija puerto o ruta, usa el caso C. Con un host exacto no se permiten sus subdominios automáticamente.

## Caso B: wildcard y dominio raíz

```yaml
in_scope:
  - "*.example.test"
out_of_scope:
  - "example.test"
  - "support.example.test"
  - "*.dev.example.test"
```

El wildcard cubre cualquier profundidad de subdominios, pero **no** el apex: `example.test` queda fuera salvo que lo añadas a `in_scope` o pongas `rules.wildcard_includes_apex: true` (solo si la política lo dice). En el ejemplo, la línea `example.test` de `out_of_scope` documenta la exclusión aunque ya no sea necesaria. `out_of_scope` prevalece. Si la política permite únicamente subdominios de un nivel, el wildcard es demasiado amplio: usa hosts exactos revisados.

## Caso C: solo una URL o una ruta

Si la política autoriza solo una ruta, un puerto o una IP, escríbelo así en el patrón:

```yaml
in_scope:
  - "https://app.example.test/portal/"   # esa ruta y lo que cuelga de ella, solo HTTPS (443)
  - "pay.example.test:8443"              # solo ese puerto
  - "203.0.113.0/24"                     # objetivos escritos como IP dentro del rango
out_of_scope:
  - "https://app.example.test/portal/admin"
nuclei:
  template_ids: ["PLANTILLA-REVISADA"]   # obligatorio para que scan ejecute Nuclei con rutas
```

Con ese scope, `scope-check https://app.example.test/admin` y `scope-check http://app.example.test/portal/` responden «FUERA DE SCOPE» e indican qué límite falla. Las rutas se normalizan antes de comparar (`/portal/../admin` no pasa). El recon sondea `https://app.example.test/portal/` y `pay.example.test:8443`, no la raíz ni los puertos por defecto. Los rangos CIDR no se expanden ni se comparan con hostnames.

**Límite:** el filtro decide qué URLs entran y qué resultados se guardan, pero una herramienta puede seguir enlaces o redirecciones fuera de la ruta. Por eso Nuclei no se ejecuta con rutas sin allowlist. Revisa en `bbhunter audit` qué se lanzó y, si la política es muy estricta, trabaja la ruta a mano con Burp/curl.

## Comprobar y registrar decisiones

```bash
bbhunter scope-check https://app.example.test/
bbhunter scope-check https://support.example.test/
bbhunter scope-check https://example.test/
bbhunter scope-check https://otro.example.invalid/
```

Compara cada salida con tu política y no solo con el YAML. El comando devuelve código 0 si está en scope y 1 si no. Aun así, no lo uses como única barrera de otras herramientas: el código de salida no sustituye tu lectura de la política. DNS, CNAME, enlaces y redirecciones tampoco amplían el alcance de forma automática.

# 07. Primera ejecución: simulación aislada

Practica el pipeline sin contactar con objetivos y sin enviar evidencia a una API. `dry_run` evita los binarios de reconocimiento/escaneo; no desactiva por sí solo la API de redacción ni las descargas de `refs sync`. Por eso en esta práctica también se deshabilita la IA y no se sincronizan referencias.

## Configuración completa de la práctica

En `config/scope.yaml`, guarda:

```yaml
program: "BBHUNTER-DEMO"
platform: "laboratorio"
policy_url: ""
in_scope: ["app.example.test"]
out_of_scope: []
rules:
  rate_limit_rps: 1
  allow_active_scan: false
  allow_automated_tools: false
  notes: "SIMULACION. No enviar sus hallazgos a ninguna plataforma."
```

En `config/settings.yaml`, usa estos ajustes. Los campos omitidos toman sus valores predeterminados; no necesitas una clave de Anthropic.

```yaml
llm_enabled: false
dry_run: true
db_path: "data/bbhunter-demo.sqlite"
reports_dir: "reports/demo"
limits:
  global_rate_limit_rps: 1
  nuclei_concurrency: 1
  http_timeout_s: 10
references:
  in_llm_prompt: false
```

## Recorrido y resultados esperados

```bash
bbhunter run
bbhunter list
bbhunter dashboard
```

La confirmación del programa sigue apareciendo aunque sea simulación. Con esta configuración, confirma únicamente la práctica descrita. El código genera un activo ficticio para el host exacto y tres candidatos de ejemplo: `.env`, `.git/config` y XSS. Si la base de demo ya contiene esos ejemplos, la deduplicación puede producir cero hallazgos nuevos.

Abre `http://127.0.0.1:8000`. Selecciona un hallazgo, revisa la evidencia ficticia y cambia su estado para practicar. Usa el ID real que muestre `list`, no presupongas que siempre empieza en 1.

```bash
bbhunter set-status 1 validated
bbhunter set-status 1 ready
bbhunter report --id 1 --pdf
```

El ID 1 es ilustrativo. Las salidas se guardan bajo `reports/demo/bbhunter-demo/`. Si falta WeasyPrint, habrá Markdown y HTML aunque el PDF falle. Detén el panel con `Ctrl+C`.

**Antes de trabajar en real:** separa base, programa y directorio de informes. Cambiar solo `dry_run: false` deja los datos ficticios en la base. Nunca envíes estos hallazgos ni los informes antiguos generados con datos de simulación.

# 08. Preparar una investigación real

## Ajustes mínimos y separación por programa

Primero termina y guarda la práctica. Después crea el programa real con `bbhunter init --program NOMBRE` (capítulo 06) y utiliza una base nueva. Los ajustes siguientes pueden ir en `programs/NOMBRE/settings.yaml`, que sustituye a `config/settings.yaml` cuando ejecutas `bbhunter -p NOMBRE ...`. No borres la base anterior para limpiar: cambia la ruta y conserva lo que necesitas.

```yaml
llm_enabled: false
dry_run: false
db_path: "data/PROGRAMA/bbhunter.sqlite"
reports_dir: "reports/PROGRAMA"
tools:
  subfinder: "subfinder"
  httpx: "httpx"
  nuclei: "nuclei"
  dalfox: "dalfox"
limits:
  global_rate_limit_rps: 1
  nuclei_concurrency: 1
  http_timeout_s: 10
references:
  in_llm_prompt: false
```

Habilita `allow_active_scan` y `allow_automated_tools` en el scope únicamente si la política permite las fases que ejecutarás. Ninguna nota escrita en `rules.notes` se convierte en un control técnico.

```bash
umask 077
mkdir -p data/casos/PROGRAMA/{scope,recon,evidencia,notas}
mkdir -p reports/PROGRAMA/final
git status --short
```

`umask 077` limita los permisos de los ficheros nuevos creados en esa shell; no cifra las evidencias ni cambia las ya existentes. `data/`, `reports/` y las configuraciones locales están ignoradas por Git. Eso no impide que se filtren mediante copias, adjuntos o sincronizadores.

## Registrar versiones y sesiones

```bash
date -u +'%Y-%m-%dT%H:%M:%SZ' > data/casos/PROGRAMA/notas/inicio.txt
python --version > data/casos/PROGRAMA/notas/python.txt
nuclei -version > data/casos/PROGRAMA/notas/nuclei.txt 2>&1
httpx -version > data/casos/PROGRAMA/notas/httpx.txt 2>&1
```

Haz lo mismo con las herramientas que realmente uses. Una nueva versión o nuevas plantillas pueden cambiar el comportamiento entre dos sesiones.

## Tasa, concurrencia y condiciones para detenerse

BBHunter usa el menor valor entre el límite del scope y el global para httpx/Nuclei, con un mínimo de 1. No sirve para límites inferiores a 1 petición por segundo. No hay un limitador compartido entre herramientas o terminales, y Dalfox usa un retraso que no equivale a un control global con sus workers predeterminados.

Ejecuta una fase cada vez. Detente ante `429`, errores repetidos de servidor, degradación observable, bloqueo o indicación del equipo. Registra la hora y la última petición; respeta `Retry-After` y las instrucciones del programa. No uses evasión del WAF para continuar una prueba bloqueada.

**Decisión antes de recon:** ¿permite el programa sondear HTTP automáticamente todo el host? Si necesitas limitar rutas, puertos, cookies o cabeceras de investigador, continúa por los capítulos manuales. El pipeline no configura esos límites.

# 09. Laboratorio local que sí puedes repetir

La simulación anterior fabrica resultados. Un laboratorio local permite aprender peticiones y navegador contra una aplicación real bajo tu control. OWASP Juice Shop documenta su despliegue con Docker [S08]. Este capítulo presupone Docker ya instalado y operativo.

## Arrancar y verificar

En una terminal del sistema donde ejecutas Docker:

```bash
docker version
docker run --rm --name bbhunter-juice \
  -p 127.0.0.1:3000:3000 bkimminich/juice-shop
```

Mantén esa terminal abierta. En otra terminal del mismo sistema de red:

```bash
curl --connect-timeout 5 --max-time 10 \
  -D /tmp/juice-headers.txt http://127.0.0.1:3000/ \
  -o /tmp/juice-home.html
```

Abre `http://127.0.0.1:3000` en el navegador. El puerto se publica solo en loopback. Si Docker y Burp están en máquinas distintas, `127.0.0.1` de una no es el de la otra: ejecuta la práctica en el mismo entorno o configura la conexión conscientemente. No publiques el laboratorio en una interfaz externa para resolverlo.

## Mapear una función con Burp

1. Abre Burp, crea un proyecto temporal y usa su navegador integrado.
2. Incluye `http://127.0.0.1:3000` en el scope de Burp.
3. Navega a la búsqueda, introduce un marcador inocuo como `BBH-DEMO-20261124` y observa `Proxy > HTTP history`.
4. Localiza la petición real de búsqueda. En una SPA puede ir a una API y no a la ruta visible del navegador.
5. Envía esa petición a Repeater y repítela sin cambios. Después cambia solo el término de búsqueda.
6. Guarda petición, respuesta y una nota del resultado. No presupongas un XSS: compruébalo según el capítulo 17.

## Por qué no basta con poner localhost y ejecutar run

El recon de BBHunter está orientado a hosts y puede probar los puertos HTTP habituales. No descubre automáticamente que el laboratorio está en `http://127.0.0.1:3000`. Tampoco conserva ese puerto como restricción del scope. Para esta práctica, usa la URL completa directamente en curl/Burp y redacta desde la plantilla manual.

Al terminar, pulsa `Ctrl+C` en la terminal de Docker o ejecuta `docker stop bbhunter-juice`. Con `--rm`, Docker elimina el contenedor cuando termina. Los resultados del laboratorio siguen siendo material de aprendizaje, no hallazgos enviables a un programa.

# 10. Metodología y cuaderno de investigación

Trabaja con una pregunta concreta en cada ciclo: «¿qué activos tengo permiso de probar?», «¿qué función procesa este dato?» o «¿esta cuenta puede acceder a un objeto que pertenece a mi segunda cuenta?». Un escáner ayuda a generar candidatos; la investigación determina si existe un límite de seguridad que se pueda cruzar.

## Secuencia y salida de cada fase

| Fase | Qué haces | Evidencia para avanzar |
|---|---|---|
| Alcance | Leer política, representar activos y anotar excepciones. | Ficha de autorización y lista revisada. |
| Descubrimiento | Consultar fuentes pasivas si están permitidas. | Candidatos con fuente y exclusiones. |
| Sondeo | Comprobar pocos hosts autorizados. | URL, puerto, estado, redirección y fecha. |
| Mapeo | Navegar funciones y observar peticiones. | Endpoint, método, parámetros, sesión y roles. |
| Hipótesis | Relacionar entrada, permiso o dato con un fallo posible. | Un caso concreto y resultado esperado. |
| Validación | Repetir una prueba mínima con control negativo. | Petición/respuesta y efecto reproducible. |
| Triaje | Descartar ruido, evaluar impacto y alcance. | Hallazgo confirmado y severidad razonada. |
| Informe | Redactar, repetir desde cero y revisar privacidad. | Informe final y adjuntos privados. |
| Seguimiento | Enviar, responder y retestar si se solicita. | ID del reporte y registro de comunicaciones. |

## Plantilla mínima de una nota de prueba

```text
Caso: PROGRAMA-001
Fecha UTC:
Activo y restriccion de politica:
Cuenta/rol de prueba:
Funcion y endpoint:
Hipotesis:
Peticion de control:
Cambio unico introducido:
Resultado esperado:
Resultado observado:
Evidencia y ficheros:
Impacto confirmado / no demostrado:
Decision: descartar / continuar / informar
```

Mantén un inventario, aunque sea TSV: `host`, `url`, `puerto`, `estado`, `tecnologia`, `sesion`, `fuente`, `ultima_revision`, `observaciones`. No descartes de entrada los 401/403: pueden ser superficies relevantes para navegar con tu cuenta; tampoco son por sí mismos una vulnerabilidad.

La metodología toma OWASP WSTG como índice de familias de pruebas [S09]. La secuencia, los criterios de parada y los ejemplos de esta guía se han adaptado al funcionamiento concreto del repositorio; no pretenden ejecutar todo WSTG con un solo comando.

# 11. Enumeración pasiva y filtrado de activos

## Qué aporta subfinder

Subfinder consulta fuentes de información para obtener nombres de subdominios [S03]. Un nombre descubierto es un candidato, no prueba de que esté autorizado, siga existiendo o pertenezca hoy a la empresa. Algunas fuentes requieren sus propias API keys; no son la clave de Anthropic.

Usa una raíz únicamente cuando la política autorice investigar sus subdominios. Si solo está permitido `app.example.test`, empieza con ese host exacto y omite el descubrimiento de toda la raíz.

```bash
subfinder -d example.test -silent \
  -o data/casos/PROGRAMA/recon/candidatos.txt
sort -u data/casos/PROGRAMA/recon/candidatos.txt \
  -o data/casos/PROGRAMA/recon/candidatos.txt
```

El resultado es un fichero de nombres, uno por línea. Puede estar vacío por ausencia de fuentes, API keys, errores o falta de resultados públicos; no significa que no existan subdominios. Revisa errores y registra el resultado.

## Filtrar sin contactar con los candidatos

El siguiente bloque usa el matcher real de BBHunter y escribe separados los permitidos y rechazados. No resuelve DNS ni hace HTTP. Aplica los mismos límites de host, puerto y ruta que el pipeline; sigue siendo necesario revisar a mano propietarios y excepciones de la política.

```bash
python - <<'PY'
from pathlib import Path
from bbhunter.scope import load_scope

base = Path('data/casos/PROGRAMA/recon')
raw = (base / 'candidatos.txt').read_text(encoding='utf-8')
targets = sorted({line.strip() for line in raw.splitlines() if line.strip()})
allowed, rejected = load_scope().filter_allowed(targets)
for filename, values in [('permitidos.txt', allowed), ('rechazados.txt', rejected)]:
    (base / filename).write_text('\n'.join(values) + '\n', encoding='utf-8')
print('Permitidos:', len(allowed), 'Rechazados:', len(rejected))
PY
```

Si trabajas sobre un único host autorizado, crea la entrada explícita en vez de enumerar una raíz:

```bash
printf '%s\n' app.example.test \
  > data/casos/PROGRAMA/recon/permitidos.txt
```

Revisa `permitidos.txt` en un editor antes del sondeo. Un CNAME a un proveedor o una IP compartida no te autoriza a probar el dominio del proveedor ni todos los servicios de esa IP. Los activos históricos requieren la misma revisión que los nuevos.

## Cuándo usar bbhunter recon

`bbhunter recon` combina este descubrimiento con sondeo activo HTTP en una sola orden. Usa semillas derivadas de `in_scope`, filtra los resultados y guarda activos en SQLite. Con `allow_active_scan: false` en el scope, `recon` se queda en la parte pasiva (sin httpx) y guarda los subdominios como `pasivo-sin-sondeo`. Si necesitas revisar candidatos antes de hacer HTTP, usa esa opción o la secuencia separada de este capítulo y del siguiente.

**Salida de fase:** lista corta de nombres revisados y rechazados documentados. Continúa solo con los permitidos por la política actual.

# 12. Sondeo web e inventario con httpx

Esta fase envía peticiones. Verifica antes que la automatización de reconocimiento esté permitida. Usa el binario de ProjectDiscovery y una lista previamente revisada [S04]. No utilices listas descargadas directamente como entrada sin filtrar.

## Definir URLs exactas

Para evitar que un hostname sin esquema provoque intentos sobre protocolos no contemplados, crea una lista de URLs y puertos autorizados. Ejemplo para un host HTTPS:

```bash
printf '%s\n' 'https://app.example.test' \
  > data/casos/PROGRAMA/recon/urls-autorizadas.txt
httpx -l data/casos/PROGRAMA/recon/urls-autorizadas.txt \
  -no-fallback-scheme -threads 1 -rate-limit 1 \
  -timeout 10 -retries 0 -status-code -title -tech-detect \
  -location -json -o data/casos/PROGRAMA/recon/httpx.jsonl
```

No se añade `-follow-redirects`. Comprueba el destino de cada 301/302 antes de visitarlo. `-no-fallback-scheme` mantiene el esquema especificado en la entrada; confirma esa opción en tu versión con `httpx -h`.

| Parámetro | Para qué sirve |
|---|---|
| `-l` | Lee las URLs que tú has autorizado, una por línea. |
| `-threads 1` | Reduce la concurrencia del proceso. |
| `-rate-limit 1` | Limita el ritmo de ese proceso; no suma el tráfico de otras herramientas. |
| `-timeout 10`, `-retries 0` | Evita esperas largas y reintentos automáticos en este sondeo. |
| `-status-code`, `-title`, `-tech-detect` | Añade pistas para priorizar; no demuestra vulnerabilidades. |
| `-location` | Muestra el destino anunciado de una redirección. |
| `-json`, `-o` | Conserva resultados estructurados como JSON por línea. |

## Interpretar y elegir

- Un 200 puede ser una página de error con código incorrecto. Comprueba título, contenido y una URL inexistente de control si está permitida.
- Un 401/403 señala una barrera; navega con tu cuenta autorizada si corresponde. No lo etiquetes como bypass.
- Un 404 no descarta el host: quizá necesites el path documentado o una sesión.
- Un fingerprint o un banner desactualizado no acredita una CVE explotable.
- Un timeout puede deberse a DNS, red, TLS o bloqueo. No concluyas «seguro» a partir de él.

El fichero producido directamente por httpx no se importa solo en BBHunter. La CLI actual no tiene comando de importación de activos. Puedes mantener este inventario externo y continuar manualmente; si quieres el pipeline, `bbhunter recon` debe poblar su base, siempre que sus restricciones encajen con la política.

**Salida de fase:** una o dos URLs concretas para estudiar, con su estado y notas. El objetivo siguiente es conocer funciones y permisos, no aumentar la lista de hosts indefinidamente.

# 13. Mapear la aplicación con Burp y navegador

Burp Community es suficiente para observar tráfico y usar Repeater; no requiere un escáner automático de pago para esta metodología. Consulta su introducción oficial [S10]. Si no está instalado en Kali, puedes instalar el paquete de la distribución:

```bash
sudo apt install -y burpsuite
burpsuite
```

## Configuración inicial

1. Crea un proyecto temporal. Si usas una edición que permite persistencia, guarda el proyecto en una ubicación privada.
2. En `Target > Scope`, incluye el esquema, host, puerto y paths autorizados; añade exclusiones. Revisa las opciones avanzadas si el alcance es por ruta [S11].
3. Usa `Proxy > Open browser` para abrir el navegador integrado. Mantén Intercept desactivado mientras recorres funciones y consúltalo solo cuando quieras detener una petición.
4. Filtra el historial para ver elementos dentro de scope. Un filtro visual no bloquea por sí mismo el tráfico; no navegues destinos excluidos ni lances acciones automáticas sobre ellos.
5. Utiliza una sesión separada para cada cuenta de prueba. No mezcles cookies de A y B.

Si utilizas un navegador externo, configura su proxy y el certificado de Burp siguiendo la documentación oficial; evita desactivar la validación TLS de todo el sistema. El navegador integrado simplifica este paso.

## Recorrido funcional

Empieza sin sesión y después con una cuenta propia. Recorre registro, inicio/cierre de sesión, perfil, búsqueda, creación y lectura de objetos de prueba, cambios de cuenta y funciones de organización si están permitidas. No dispares correos, pagos o acciones irreversibles solo por completar una lista.

Para cada función apunta:

| Campo | Ejemplo de nota |
|---|---|
| Acción visible | Abrir un documento que creé con la cuenta A. |
| Petición real | `GET /api/documents/ID_A` al host autorizado. |
| Entradas | Path ID, query, JSON, formularios, cabeceras relevantes. |
| Sesión y rol | Cuenta A, usuario normal, organización de prueba A. |
| Objeto y propietario | ID_A pertenece a A; contenido sintético reconocible. |
| Respuesta | Estado, campos relevantes y si aparecen datos privados. |
| Hipótesis | ¿B puede obtener el mismo objeto de A sin permiso? |

Los fragmentos tras `#` en una URL de SPA no se envían necesariamente al servidor. Busca el endpoint real en el historial. Del mismo modo, que el JavaScript mencione un endpoint no implica que esté activo ni autorizado.

## Repetir una petición controlada

En el historial, clic derecho y `Send to Repeater`. Envía primero sin cambios; debe reproducir la navegación. Duplica la pestaña, cambia un único dato y compara respuestas [S12]. Guarda ambos casos. Evita seguir redirecciones fuera de scope o generar nuevas peticiones sin revisar su destino.

**Salida de fase:** un mapa de endpoints y dos o tres hipótesis concretas, cada una vinculada a una función y a un permiso esperado.

# 14. Peticiones y evidencia con curl

Curl permite conservar una petición reproducible y separar cabeceras de cuerpo [S13]. Los ejemplos no siguen redirecciones: no añadas `-L` sin revisar los destinos. No uses `-k` para ocultar errores TLS en la evidencia final.

## Petición de control a una URL autorizada

```bash
curl --connect-timeout 5 --max-time 15 \
  -D data/casos/PROGRAMA/evidencia/control.headers \
  -o data/casos/PROGRAMA/evidencia/control.body \
  'https://app.example.test/ruta-autorizada'
```

`-D` guarda cabeceras, `-o` guarda el cuerpo y los límites de tiempo evitan esperas indefinidas. No confíes solo en `curl -I`: HEAD puede comportarse de forma distinta de GET y no demuestra el contenido accesible.

## Parámetro de búsqueda sin problemas de escape

```bash
curl --get --data-urlencode 'q=BBH-20261124-UNICO' \
  --connect-timeout 5 --max-time 15 \
  -D data/casos/PROGRAMA/evidencia/busqueda.headers \
  -o data/casos/PROGRAMA/evidencia/busqueda.body \
  'https://app.example.test/search'
```

El path y el parámetro son ilustrativos: usa los observados en tu sesión. Busca el marcador en la respuesta y anota en qué contexto aparece. Que una cadena se refleje no significa que se ejecute como JavaScript.

## Sesión propia sin poner el token en el comando

Guarda únicamente las cabeceras de tu sesión de prueba en un fichero privado, revisado en un editor. Ejemplo de estructura, con valor ficticio:

```text
Authorization: Bearer TOKEN_DE_LA_CUENTA_DE_PRUEBA
```

```bash
chmod 600 data/casos/PROGRAMA/evidencia/sesion-a.headers
curl -H @data/casos/PROGRAMA/evidencia/sesion-a.headers \
  --connect-timeout 5 --max-time 15 \
  -D data/casos/PROGRAMA/evidencia/autenticada.headers \
  -o data/casos/PROGRAMA/evidencia/autenticada.body \
  'https://app.example.test/api/recurso-propio'
```

Sustituye la autenticación por la que realmente utiliza la aplicación; no inventes tokens ni uses secretos descubiertos para acceder a otro servicio. Los ficheros siguen conteniendo credenciales: redacta una copia para compartir y conserva el original de manera privada según las reglas del programa.

**Control de calidad:** puedes explicar qué parte de la respuesta demuestra el efecto y repetirlo sin depender de una captura aislada. No incluyas cookies completas, correos personales o datos de terceros en adjuntos innecesarios.

# 15. Descubrimiento de rutas y servicios

## Rutas antes que fuerza bruta

Empieza por enlaces y tráfico que ya utiliza la aplicación, documentación publicada y ficheros anunciados. `robots.txt` y `sitemap.xml` pueden ofrecer pistas, pero no autorizan rutas ni constituyen una filtración por sí mismos. Pide cada recurso únicamente si ese path está permitido.

```bash
curl --connect-timeout 5 --max-time 10 \
  -D data/casos/PROGRAMA/recon/robots.headers \
  -o data/casos/PROGRAMA/recon/robots.txt \
  'https://app.example.test/robots.txt'
```

Para una aplicación cuyo scope es solo `/portal/`, no pruebes `/robots.txt` fuera de ese permiso. Revisa JavaScript y esquemas de API obtenidos legítimamente dentro del alcance; anota rutas y parámetros para confirmarlos con tu propia sesión.

La versión actual de BBHunter no ejecuta crawler, Wayback, Katana o descubrimiento de directorios. Si necesitas otra herramienta, revisa qué métodos, redirects y paths puede generar, cómo fija su scope y si el programa permite esa automatización. Un límite de peticiones no evita salir del path autorizado.

## Puertos: paso opcional, con permiso específico

No escanees puertos sobre una IP de CDN o un proveedor solo porque el dominio apunte a ella. Si el programa permite sondeo de servicios sobre una IP concreta y propia del alcance, Naabu puede comprobar puertos limitados [S14]. No está integrado en `bbhunter run`.

Ejemplo para un laboratorio propio en `127.0.0.1`, con pocos puertos:

```bash
naabu -host 127.0.0.1 -p 80,443,3000 \
  -scan-type c -rate 5 -c 1 -silent \
  -o data/casos/PROGRAMA/recon/puertos-lab.txt
```

`-scan-type c` usa conexión TCP; `-rate` se expresa en paquetes por segundo, no en peticiones HTTP. Confirma la ayuda de la versión instalada. Para un programa real, sustituir la IP requiere que el activo y la técnica estén autorizados; no es un paso obligatorio para investigar una web.

## Crear una lista de endpoints candidata

Anota la URL exacta con método, parámetros, rol y procedencia. Mantén separadas las rutas observadas de las supuestas. Marca como descartadas las que no encajan en la política. No automatices listas históricas con tokens, enlaces firmados o acciones destructivas.

**Salida de fase:** conoces las entradas accesibles de la función elegida y puedes hacer una petición normal de control. Si no la tienes, vuelve al mapeo antes de lanzar un escáner.

# 16. Nuclei: usar plantillas con criterio

Nuclei ejecuta comprobaciones definidas por plantillas. Su documentación distingue selección de plantillas, límites, protocolos, redirecciones y pruebas OAST [S05]. La severidad indicada en una plantilla no dice si su prueba es inocua ni si la política la permite.

## Preparar una comprobación acotada

1. Identifica una hipótesis y una plantilla concreta que la compruebe.
2. Revisa el YAML: destinos, métodos, paths, payloads, callbacks, número aproximado de solicitudes y condiciones del matcher.
3. Si hay escritura, autenticación intrusiva, rutas no permitidas o destinos externos no autorizados, no la ejecutes.
4. Copia solo las plantillas revisadas a `data/casos/PROGRAMA/plantillas/`. Una firma verifica procedencia, no la adecuación a tu programa.
5. Empieza con una URL y una plantilla, observando el tráfico y el resultado.

```bash
nuclei -update-templates
mkdir -p data/casos/PROGRAMA/plantillas
```

Después de copiar y revisar una plantilla con el nombre local `comprobacion.yaml`:

```bash
nuclei -u 'https://app.example.test' \
  -t data/casos/PROGRAMA/plantillas/comprobacion.yaml \
  -rate-limit 1 -concurrency 1 -bulk-size 1 \
  -timeout 10 -retries 0 -disable-redirects -no-interactsh \
  -jsonl -o data/casos/PROGRAMA/evidencia/nuclei.jsonl
```

El fichero de plantilla no se incluye como un escaneo universal listo para ejecutar: debe corresponder al caso que has elegido. `-no-interactsh` excluye las plantillas que requieren ese servicio OAST. Tampoco garantiza que cualquier plantilla arbitraria carezca de destinos externos: debes revisar su contenido.

## Evaluar un resultado

Guarda ID y versión de la plantilla, URL, fecha y salida. Examina la petición exacta y la condición que produjo el match. Repite solo la comprobación necesaria con curl/Burp y un control negativo. Un 200 genérico o una palabra presente en una página de error pueden producir un candidato falso.

La salida directa de este comando no se importa automáticamente en BBHunter. Mantén las evidencias junto al informe manual. No copies un resultado a la plataforma sin comprobar el impacto.

## Qué cambia si usas bbhunter scan

`bbhunter scan` toma las URLs de SQLite y llama Nuclei con la política del bloque `nuclei:` del scope: plantillas (`-t`), IDs (`-id`), tags (`-tags`), tags excluidas (`-etags`), severidades y `-no-interactsh` salvo que lo permitas. Añade tasa, concurrencia, cabeceras del programa y proxy. Después puede ejecutar Dalfox sobre URLs con `?`.

Úsalo solo cuando la política permita lo que realmente ejecutan esas herramientas y hayas revisado su configuración y plantillas instaladas. La allowlist se define por programa en el scope, no con una opción de la CLI, para que quede registrada junto a su alcance. La confirmación previa al escaneo muestra la política aplicada.

# 17. XSS: de una reflexión a una prueba válida

## Comenzar por una entrada real

Elige un parámetro que hayas observado en una función permitida. Haz una petición normal, introduce un marcador único y busca la cadena en la respuesta y en el DOM. Anota si aparece como texto HTML, atributo, cadena JavaScript, URL o contenido generado por el cliente.

Una reflexión escapada como `&lt;script&gt;` en texto no demuestra XSS. Tampoco basta con que el payload aparezca en el código fuente, una extensión del navegador ejecute algo o el caso requiera pegar JavaScript en la consola.

## Prueba manual mínima

Si el contexto y la política permiten una prueba de XSS, usa una señal benigna solo en tu sesión de prueba, por ejemplo `alert('BBH-POC')`. No extraigas cookies ni envíes datos a un servicio externo. En un contexto de HTML sin escape, un ejemplo didáctico de entrada es:

```text
<script>alert('BBH-POC')</script>
```

Para enviarlo en un parámetro de búsqueda observado:

```bash
curl --get --data-urlencode "q=<script>alert('BBH-POC')</script>" \
  --connect-timeout 5 --max-time 15 \
  -D data/casos/PROGRAMA/evidencia/xss.headers \
  -o data/casos/PROGRAMA/evidencia/xss.body \
  'https://app.example.test/search'
```

Curl guarda la reflexión; no ejecuta JavaScript. Abre la petición equivalente en el navegador bajo tu control y confirma si el código se ejecuta en el origen afectado. Este payload no funciona en todos los contextos ni pretende evitar filtros. Si CSP u otra defensa impide la ejecución, documéntalo y no declares ejecución confirmada.

## Dalfox v2 como apoyo opcional

Solo si el escaneo XSS automatizado está permitido, verifica `dalfox url --help`. El ejemplo siguiente usa la interfaz v2 consultada y reduce superficie y concurrencia [S07]:

```bash
dalfox url 'https://app.example.test/search?q=BBH-POC' \
  -p q --worker 1 --delay 1000 --timeout 10 \
  --skip-mining-all --skip-bav --skip-headless \
  --format jsonl --output data/casos/PROGRAMA/evidencia/dalfox.jsonl
```

No añadas blind callbacks, evasión WAF ni seguimiento de redirecciones fuera de scope. El escáner envía múltiples payloads; si solo tienes permiso para comprobaciones puntuales, utiliza la prueba manual. Repite en navegador cualquier resultado que vayas a reportar.

## Limitaciones de la integración actual

El recon suele guardar URLs de host sin query y no hay crawler, así que Dalfox puede no ejecutarse sobre candidatos útiles. Además, `scan.py` solicita `--format json` y lo procesa como JSON por línea; la interfaz v2 consultada distingue JSON de JSONL. Un resultado vacío de esta integración no descarta XSS. La guía no presupone compatibilidad con la interfaz v3.

**Evidencia para informar:** parámetro y URL reproducible, precondiciones, navegador, petición/respuesta relevante, captura de la señal benigna y explicación del origen y de la interacción necesaria. No afirmes robo de cookies HttpOnly o toma de cuenta sin demostrar un escenario autorizado que lo permita.

# 18. Validar exposiciones y descartar falsos positivos

BBHunter agrupa bajo `exposure` situaciones muy diferentes: configuraciones expuestas, ficheros, backups, paneles y otras etiquetas. El vector por defecto de esa clase supone alta pérdida de confidencialidad. Tu trabajo es comprobar si ese supuesto se cumple.

## Procedimiento para un recurso candidato

1. Comprueba que la URL completa está dentro del alcance, incluida la ruta.
2. Haz una petición sin sesión y guarda cabeceras y el fragmento mínimo necesario del cuerpo.
3. Compara con una ruta inexistente para detectar respuestas genéricas o soft 404, solo si esa petición de control está permitida.
4. Identifica qué información real y no pública aparece. Diferencia variables de ejemplo, datos del laboratorio, recursos públicos y secretos aparentes.
5. Repite una vez desde una sesión limpia si necesitas demostrar ausencia de autenticación. Detente cuando haya evidencia suficiente.

Para un endpoint ya observado y permitido, sin descargar respuestas grandes:

```bash
curl --connect-timeout 5 --max-time 10 --max-filesize 16384 \
  -D data/casos/PROGRAMA/evidencia/recurso.headers \
  -o data/casos/PROGRAMA/evidencia/recurso.body \
  'https://app.example.test/ruta-del-recurso-confirmado'
```

`--max-filesize` limita la transferencia que acepta curl; puede dar error y dejar evidencia parcial. No es permiso para descargar datos personales. Si la sensibilidad se aprecia antes, detente y conserva solo el fragmento necesario. Evita abrir o descargar copias de seguridad completas para «aumentar el impacto».

## Cómo valorar lo encontrado

| Observación | Qué falta para llamarlo vulnerabilidad |
|---|---|
| 200 en `/.env` | Que el contenido sea un fichero sensible real, no HTML genérico o un ejemplo público. |
| `/.git/config` devuelve texto | Qué información no pública queda expuesta; no presupongas acceso a todo el repositorio. |
| Panel de administración visible | Un fallo de control o exposición relevante; una pantalla de login no basta. |
| Cabecera o versión de servidor | Un impacto aceptado por la política, no solo una recomendación de endurecimiento. |
| Cadena que parece una API key | Evidencia de exposición y contexto; no uses la clave para explorar otros servicios. |

## Minimizar datos y redactar con precisión

Si ves un secreto o datos ajenos, registra la ubicación, la hora y una muestra redactada suficiente para que el equipo la reconozca. No enumeres más registros ni autentiques con credenciales encontradas sin una autorización adicional explícita del programa para esa verificación.

En el impacto separa «confirmado: el fichero permite leer X sin sesión» de «posible: determinadas claves podrían permitir Y; no se probó su uso». El código de BBHunter no hace esa distinción por ti y sus plantillas pueden sugerir consecuencias que debes corregir.

**Salida de fase:** un recurso concreto y una explicación de qué confidencialidad se vulnera, o una razón documentada para descartar el candidato.

# 19. Autorización, API y lógica con cuentas propias

Los fallos de autorización suelen requerir entender quién posee un objeto y qué permisos debería tener cada cuenta. BBHunter no los comprueba sistemáticamente. Burp Repeater permite comparar peticiones controladas sin enumerar IDs de terceros.

## Comprobar un acceso horizontal: A y B

1. Crea dos cuentas de prueba permitidas, A y B, con el mismo rol y sin pertenencia compartida. Si existe multiempresa, usa dos organizaciones de prueba independientes.
2. Con A, crea un objeto sintético reconocible: documento, nota o proyecto. Anota su ID exacto y su configuración de privacidad.
3. Con B, crea otro objeto propio. Comprueba que B puede leer su propio objeto: es el control positivo de sesión y endpoint.
4. Captura la lectura del objeto de A y envíala a Repeater.
5. Duplica la petición y sustituye únicamente la autenticación por la de B. Mantén el ID de A, que también te pertenece como investigador.
6. Envía una vez y compara. Debe denegar acceso al contenido privado de A. Comprueba si la respuesta revela realmente ese contenido.
7. Repite con sesión limpia para descartar confusión de cookies o una caché local. Detente al confirmar el fallo mínimo.

Ejemplo de estructura HTTP. Usa los endpoints que hayas observado y las sesiones de tus cuentas; estos valores son ficticios:

```http
GET /api/documents/ID_DEL_OBJETO_DE_A HTTP/1.1
Host: app.example.test
Authorization: Bearer TOKEN_DE_B
Accept: application/json
```

**Esperado:** B no recibe el documento privado de A. **Observado que sería relevante:** la respuesta incluye el marcador sintético guardado por A y demuestra lectura no autorizada. Un 200 con error JSON, un ID visible sin contenido o un objeto configurado como público no demuestran el fallo descrito.

## Separar lectura y escritura

No infieras que puedes editar o borrar por haber leído. Una prueba de escritura requiere permiso de la política y debe afectar solo a objetos tuyos, con un cambio pequeño y reversible. No pruebes funciones administrativas o acciones sobre usuarios reales para ampliar el impacto.

Guarda una matriz: cuenta/rol, organización, objeto, acción, resultado esperado y observado. Revisa también si el permiso es heredado por pertenencia a un equipo, si el enlace es compartible o si existe una función pública documentada.

## Autenticación y sesiones

Con tu propia cuenta puedes observar si el cierre de sesión invalida la sesión según el diseño, si un cambio sensible requiere la comprobación prevista y si la recuperación de cuenta se dirige al usuario correcto. Registra el flujo normal primero. No hagas fuerza bruta, password spraying, credential stuffing ni pruebas masivas de códigos.

Para lógica de negocio, escribe la regla funcional antes de probarla: «un usuario básico no puede exportar un recurso privado ajeno», por ejemplo. Usa datos sintéticos y detente si el test requiere un pago real, envío de correo a terceros o un cambio irreversible no autorizado.

**Salida de fase:** un límite de permisos demostrado con dos cuentas controladas, sin enumeración de usuarios ni datos ajenos. Si solo hay una sospecha, continúa investigando o descártala; no la presentes como impacto confirmado.

# 20. Otras familias: decidir qué validar

Este capítulo es una lista de hipótesis, no una instrucción de ejecutar payloads de todas las clases. Amplía una prueba solo cuando la política permita la técnica y tengas una forma de demostrar el efecto con datos propios. Para procedimientos más amplios, consulta la categoría concreta de WSTG [S09].

| Familia | Comprobación inicial y evidencia necesaria | Límite práctico |
|---|---|---|
| CSRF | Identifica una acción sensible propia y comprueba si una petición desde otro origen puede realizarla con la sesión del navegador. Un token ausente no basta: observa cookies SameSite y efecto real. | Solo cambios reversibles en tu cuenta. No envíes enlaces a usuarios. |
| CORS | Revisa qué origen puede leer qué respuesta con credenciales y confirma lectura desde un origen de prueba bajo tu control. Una cabecera permisiva aislada no acredita filtración. | Nada de datos ajenos ni publicación del PoC. |
| Redirección abierta | Comprueba una navegación a un dominio benigno tuyo y registra la URL inicial/final. Explica la consecuencia aceptada por la política. | No montes phishing ni recojas credenciales. |
| Subida de archivos | Usa un fichero de texto o imagen con marcador propio. Observa dónde se sirve, permisos, tipo y aislamiento. | No subas webshells, malware ni archivos enormes. |
| Caché | Compara respuestas de tus cuentas con marcadores propios y evidencia del estado de caché. | No contamines una caché compartida ni afectes a otros usuarios. |
| SSRF | Empieza por entender la función que procesa URLs. Una llamada a un endpoint benigno propio solo se prueba si OAST/egress está permitido. | No explores redes internas, metadatos cloud o credenciales. |
| Inyección SQL u otra inyección | Correlaciona entradas con un comportamiento anómalo y controles estables. Una respuesta 500 o un mensaje de error no basta. | No extraigas tablas, ejecutes comandos ni uses pruebas de carga/tiempo prolongado. |
| Dependencia/CVE | Confirma componente, versión real y precondiciones. Un banner o matcher de versión es un candidato. | Si validar exige explotación intrusiva, consulta al programa con la evidencia disponible. |
| Takeover de subdominio | Contrasta DNS, proveedor y mensaje de servicio no configurado. | No registres ni reclames recursos, marcas o cuentas ajenas para probarlo. |

## Cuándo detener el análisis técnico

Si la prueba mínima ya demuestra el límite roto, conserva evidencia suficiente y pasa al informe. No es necesario encadenar hasta una toma de control para que el equipo pueda estudiar un fallo con impacto claro. Si el programa exige otra prueba, acuerda el paso siguiente por su canal de triaje.

Si un candidato solo muestra ausencia de una cabecera, un puerto abierto, una versión o un error genérico, contrasta si la política acepta ese tipo de información y qué impacto falta. Documentar «no confirmado» en el cuaderno es una conclusión útil.

**Salida de fase:** hipótesis descartadas con motivo, pruebas pendientes claramente delimitadas y, si procede, un hallazgo mínimo confirmado. La calidad procede de esa separación.

# 21. Evidencia, impacto y severidad

## Paquete mínimo para reproducción

- Fecha y hora UTC de la validación, URL completa, método y rol requerido.
- Precondiciones: cuentas de prueba, objeto creado, flags de privacidad y estado de sesión.
- Petición original de control y petición modificada; resalta el único cambio relevante.
- Respuesta o efecto observado, junto con el resultado que debería producirse.
- Captura o vídeo corto como apoyo; el texto debe permitir repetir la prueba sin depender del vídeo.
- Herramienta/versión si afecta a la reproducción y número aproximado de solicitudes.
- Limitaciones de la prueba y medidas de limpieza de tus datos sintéticos.

Conserva originales privados y una copia redactada para el envío. Usa nombres como `01-control.txt`, `02-prueba.txt` y `03-resultado.png`. Sustituye secretos por etiquetas consistentes como `[TOKEN_A]` o `[VALOR_REDACTADO]`, conservando los nombres de cabeceras y la estructura. Si el equipo necesita el original, utiliza el mecanismo privado que indique.

```bash
sha256sum data/casos/PROGRAMA/evidencia/01-control.txt \
  data/casos/PROGRAMA/evidencia/02-prueba.txt \
  > data/casos/PROGRAMA/evidencia/SHA256SUMS.txt
```

El hash facilita comprobar qué ficheros conservaste; no demuestra por sí mismo el fallo. Si no has creado esos ficheros, usa los nombres reales. No envíes por error `sesion-a.headers` o una base SQLite entera como evidencia.

## Describir impacto sin exagerarlo

Escribe la consecuencia de seguridad, no una lista de ataques posibles. «B lee el documento privado creado por A sin pertenecer a su organización» es más útil que «vulnerabilidad crítica que compromete toda la empresa».

Separa tres niveles: **confirmado** con evidencia, **alcance observado** con cuentas propias y **consecuencias potenciales no verificadas**. Si solo has probado lectura de un objeto tuyo, no afirmes escritura, administración o acceso masivo.

## Calcular severidad y elegir taxonomía

BBHunter calcula CVSS v3.1 con vectores por defecto de su base: exposure 7.5, XSS reflejado 6.1 y genérico 5.3. Son supuestos de clase, no evaluaciones específicas de tu caso. FIRST define las métricas de CVSS v3.1 [S15]. Revisa acceso por red, complejidad, privilegios, interacción, alcance y efectos en confidencialidad, integridad y disponibilidad; publica el vector junto al número si lo utilizas.

Bugcrowd VRT clasifica tipos y variantes de vulnerabilidad [S16]. El mapeo interno Critical=P1, High=P2, etc. es una aproximación y no sustituye esa taxonomía. En HackerOne usa la clasificación y la calculadora que pida el formulario. Si el programa solicita otra versión de CVSS, sigue esa instrucción: BBHunter no implementa automáticamente CVSS v4.

Los importes de `vrt_mapping.yaml` y las estadísticas de reportes similares no predicen una recompensa. Revisa la elegibilidad y tabla del programa; no incluyas una exigencia de pago basada en los valores internos de BBHunter.

# 22. Triaje, redacción y exportación en BBHunter

## Orden recomendado de estados

`new` es un candidato; `validated` indica que tú lo has reproducido; `false_positive` lo descarta por falta de fallo; `duplicate` registra una repetición conocida; `ready` indica que el texto y los adjuntos están revisados; `reported` se aplica después del envío. Estos estados son locales y manuales: cambiar una etiqueta no valida ni comunica nada a la plataforma.

```bash
bbhunter list --status new
bbhunter dashboard --host 127.0.0.1 --port 8000
bbhunter set-status 3 validated
```

Usa el ID que corresponda a tu base y al programa activo. El panel permite ver evidencia, referencias y Markdown, cambiar estado y generar MD/HTML. No tiene editor de texto, carga de adjuntos ni control de acceso para publicarlo en una red. Mantenlo en loopback y detén el proceso al terminar.

## Redacción sin IA, recomendada para empezar

Con `llm_enabled: false`, `enrich` copia textos base y listas de validación. No aporta evidencia nueva y el resultado requiere adaptar cada párrafo a lo observado.

```bash
bbhunter enrich --id 3
bbhunter report --id 3
```

Los textos curados cubren principalmente exposiciones y XSS reflejado. Las demás clases usan un fallback genérico. No conviertas un «por determinar» en una conclusión al copiar el informe.

## Activar Anthropic si está permitido

La IA es opcional. `llm.py` envía nombre, URL, parámetro, severidad, hasta 3.000 caracteres de evidencia y, si está habilitado, referencias similares. La evidencia se envía con los secretos enmascarados (contraseñas, claves, tokens, cookies, claves privadas), y con `llm_evidence: "none"` no se envía nada del objetivo. El enmascarado es por patrones: no detecta datos personales ni secretos con formatos no previstos. Actívala únicamente si la política permite usar ese servicio.

Configura `llm_enabled: true` y el ID de modelo disponible en tu cuenta según la documentación oficial [S17]. La variable de entorno tiene prioridad sobre el YAML. Para no escribir la clave en el historial Bash:

```bash
read -rsp 'Clave Anthropic: ' ANTHROPIC_API_KEY
export ANTHROPIC_API_KEY
printf '\n'
bbhunter enrich --id 3 --force
unset ANTHROPIC_API_KEY
```

`--force` vuelve a redactar el contenido guardado. `--final` elige el modelo configurado como final; no mejora la evidencia ni sustituye la revisión. Si falla la API, el programa cae a plantillas locales. La procedencia y el error de fallback no se conservan de forma suficiente en la base: revisa el texto y no deduzcas que funcionó solo por ver «enriquecido».

## Exportar y congelar la versión que vas a enviar

```bash
bbhunter set-status 3 ready
bbhunter report --status ready --pdf
find reports/PROGRAMA -maxdepth 3 -type f
```

La salida real se guarda en `reports_dir/<slug-del-programa>/`. El PDF es opcional y puede fallar conservando MD/HTML. Cambia a ready solo después de revisar el caso; `report --status ready` filtra por etiqueta, no examina el contenido. No combines `--id` y `--status` esperando una doble barrera: la implementación prioriza el ID.

Copia el Markdown a una carpeta `final/` y edita esa copia; regenerar vuelve a escribir los nombres de salida. Completa precondiciones, pasos observados, capturas y severidad. Retira estimaciones de recompensa y texto de ejemplo. El HTML de informe escapa la evidencia y los textos (corregido; ver capítulo 29), así que puedes abrirlo en el navegador. Aun así, el Markdown es la versión que debes revisar y pegar en la plataforma.

**Hallazgos manuales:** no existe `bbhunter add` ni importación desde Burp en la CLI. Usa directamente `docs/plantilla_informe.md`; puedes elaborar un informe completo sin introducirlo en SQLite. No necesitas inventar un hallazgo automático para aprovechar la guía.

# 23. Construir un informe listo para revisión

## Estructura que debe poder entender el triaje

1. **Título:** clase, ubicación y efecto concreto. Ejemplo: «Acceso entre cuentas a documentos privados mediante ID sin control de propietario».
2. **Resumen:** qué ocurre, con qué rol y qué límite de seguridad se rompe, en pocas frases.
3. **Activo y alcance:** URL/endpoint y entrada del programa que lo autoriza. Incluye método y parámetro.
4. **Precondiciones:** cuentas/roles, objetos de prueba y configuración relevante.
5. **Pasos numerados:** acciones completas y ordenadas desde una sesión nueva, con petición de control y modificación.
6. **Resultado esperado y observado:** qué debería denegarse y qué sucedió realmente.
7. **Evidencia:** fragmentos relevantes y adjuntos privados que correspondan exactamente a esos pasos.
8. **Impacto:** consecuencia demostrada y límites de lo que no verificaste.
9. **Severidad propuesta:** taxonomía/vector y justificación, si el programa lo requiere.
10. **Remediación y limpieza:** recomendación ligada a la causa y datos de prueba que eliminaste o dejaste identificados.

La plantilla reutilizable se encuentra en `docs/plantilla_informe.md`. Cópiala a `reports/PROGRAMA/final/` y reemplaza todos sus campos. Puedes redactar en el idioma aceptado por el programa; evita traducciones que cambien precondiciones o impacto.

## Ejemplo completo: acceso horizontal a un documento

**EJEMPLO FICTICIO.** Los IDs y resultados siguientes ilustran la redacción de una prueba que tendrías que realizar en un objetivo autorizado. No son un hallazgo de esta revisión ni deben enviarse como evidencia.

### Título y resumen

**Lectura de documentos privados de otra cuenta mediante GET /api/documents/{id}.**

Un usuario autenticado normal puede leer un documento privado de otra cuenta si conoce su identificador. Lo comprobé con dos cuentas propias sin permisos compartidos: la cuenta B recibió el contenido del documento creado por A. No probé objetos de otros usuarios ni capacidad de modificación.

### Activo, fecha y precondiciones

- Activo de ejemplo: `https://app.example.test`, autorizado expresamente en la política del programa ficticio.
- Endpoint: `GET /api/documents/{id}`; parámetro afectado: ID en la ruta.
- Validación ilustrativa: 2026-11-24, 12:00 UTC. En un informe real usa la fecha observada.
- Dos cuentas propias A y B, rol normal, sin organización compartida ni enlaces públicos.
- Con A se creó un documento privado ID `doc-a-1042`, contenido `BBH-PRIVADO-A-20261124`.
- Con B se creó un documento propio ID `doc-b-2051` para comprobar que su sesión funcionaba.

### Pasos de reproducción

1. Iniciar sesión como A. Crear un documento privado con el marcador indicado y confirmar que no está compartido.
2. Abrir el documento y capturar `GET /api/documents/doc-a-1042`. Guardar la respuesta que contiene el marcador.
3. En una sesión separada como B, abrir `doc-b-2051` para verificar que la sesión B tiene acceso normal a sus propios documentos.
4. En Repeater duplicar la petición del paso 2 y sustituir solo el token de A por el token de B. No conservar otra cookie de A.
5. Enviar la petición modificada una vez. Observar que la respuesta devuelve el documento de A y su marcador, pese a no existir permiso de compartición.
6. Repetir la lectura con una sesión B nueva para confirmar que no depende de una mezcla local de sesiones.

### Petición modificada y respuesta ilustrativas

```http
GET /api/documents/doc-a-1042 HTTP/1.1
Host: app.example.test
Authorization: Bearer [TOKEN_B_REDACTADO]
Accept: application/json
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"id":"doc-a-1042","private":true,"content":"BBH-PRIVADO-A-20261124"}
```

**Esperado:** B no obtiene el contenido del documento privado de A; la aplicación deniega la autorización o no revela el recurso. **Observado en este ejemplo ficticio:** B obtiene el marcador privado. En un caso real, adjunta las respuestas originales redactadas y los controles que respaldan esa afirmación.

### Impacto y límites

Se demuestra pérdida de confidencialidad entre dos cuentas de prueba. La condición es estar autenticado y conocer el ID del objeto de la otra cuenta. No se ha demostrado enumeración de IDs, escritura, borrado ni acceso masivo; no se han consultado datos de terceros. El efecto sobre objetos de clientes reales queda a evaluación del equipo.

### Severidad y remediación

Propuesta razonada para este ejemplo: CVSS v3.1 4.3, `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`, asumiendo lectura limitada y las precondiciones descritas. El impacto real, sensibilidad de documentos y condiciones del programa pueden cambiar esta evaluación. No conviertas este vector en un valor fijo para todos los IDOR.

Aplicar comprobación de autorización sobre cada objeto y operación en el servidor; verificar propietario y permisos efectivos para la cuenta solicitante, con denegación por defecto. Incorporar pruebas de regresión entre cuentas/organizaciones de prueba. Usar IDs impredecibles puede reducir descubrimiento, pero no sustituye la autorización.

### Adjuntos y cierre

En un informe real adjuntaría `01-control-a.txt`, `02-control-b.txt`, `03-lectura-b-de-a.txt` y una captura que identifique ambas cuentas de prueba con datos redactados. Indicaría también si se eliminaron los dos documentos tras capturar la evidencia. Aquí se describen los adjuntos esperados; no se han fabricado esos ficheros como si fueran una prueba real.

## Revisión antes del envío

Repite tus pasos en una sesión nueva usando únicamente lo que dice el informe. Si necesitas un dato que falta, añádelo. Comprueba que el ID, parámetro, capturas y respuesta coincidan y que cada afirmación de impacto tenga evidencia. Agrupa endpoints con la misma causa cuando la política lo indique; no dividas artificialmente una sola causa para multiplicar reportes.

# 24. Enviar y atender el triaje

## HackerOne

Entra en la página oficial del programa y abre `Submit Report`. Selecciona activo, plantilla y tipo de debilidad; indica la severidad cuando el formulario la solicite. Pega el resumen y los pasos reproducibles en los campos previstos, añade impacto y adjunta evidencia privada. Revisa todos los campos y la vista previa antes de enviar [S18].

La guía oficial consultada recomienda adjuntar los vídeos directamente, en vez de enlazarlos desde un sitio externo. El formulario y sus requisitos pueden cambiar; la política específica y lo que aparece en pantalla son la referencia operativa. Un PDF puede apoyar la revisión, pero no sustituye los campos obligatorios ni los pasos escritos.

## Bugcrowd

Desde el brief, abre `Submit Report`; completa título, target, clasificación VRT, ubicación y descripción con reproducción e impacto. Añade los adjuntos y revisa el borrador antes de enviar [S19]. Elige el target del alcance que corresponda; no uses una opción genérica para eludir una exclusión.

Las recomendaciones de severidad no garantizan la prioridad final: el equipo evalúa el efecto del caso. La política de divulgación sigue aplicando al hallazgo aunque sea duplicado o se cierre sin recompensa [S19].

## Registrar el envío y responder

Guarda el ID del reporte, enlace privado, fecha UTC y copia exacta del texto enviado. Para un hallazgo que sí está en SQLite:

```bash
bbhunter set-status 3 reported
```

Eso actualiza solo BBHunter. En tu cuaderno registra estados de plataforma como recibido, petición de información, triaged, duplicate, informative, resolved o rewarded; no todos tienen equivalente en el programa local.

Si solicitan información, contesta con el paso concreto, evidencia nueva mínima y las precondiciones que aclaren el problema. Si ya no se reproduce, dilo y proporciona la fecha de la última validación. No crees otro reporte igual para reclamar atención.

Si se cierra como duplicado, no intentes consultar reportes privados de otras personas; pregunta con respeto si falta entender la causa o el alcance. Si discrepas del impacto, explica la diferencia con evidencia, sin amenazar ni condicionar la confidencialidad a un pago.

## Aceptación, recompensa y retest

Un informe claro facilita la revisión, pero no garantiza estudio prioritario, aceptación ni pago. Influyen elegibilidad, política, reproducibilidad, impacto, conocimiento previo y decisión del programa. Sigue las instrucciones de la plataforma para cualquier verificación de identidad o configuración de cobro; no adjuntes documentación personal al informe técnico.

Haz retest cuando el programa lo solicite o su política lo contemple: repite la prueba mínima original con tus objetos de prueba, comprueba el control normal y documenta fecha y resultado. No amplíes el alcance aprovechando el retest. Publica un writeup solo según la autorización y condiciones de divulgación del programa.

# 25. Solución de problemas y diagnósticos

## Instalación y rutas

| Síntoma | Qué revisar y qué hacer |
|---|---|
| `bbhunter: command not found` | En Kali, activa `source .venv/bin/activate` y comprueba `command -v bbhunter`. Ejecuta `python -m bbhunter.cli --help` para verificar el módulo. |
| `.venv/bin/activate` no existe | Puede ser una venv de Windows o una carpeta distinta. Crea una venv Linux nueva; no intentes usar `.venv/Scripts` en Kali. |
| `go install` falla por versión | Mira `go version` y el requisito de la release. Actualiza según Go oficial; no omitas el error y supongas que la herramienta quedó instalada. |
| Error de compilación de Naabu por pcap | Instala `libpcap-dev` y herramientas de compilación; vuelve a instalar solo el binario fallido. |
| `httpx` tiene otras opciones | `type -a httpx` identifica el conflicto. Fija la ruta al binario de ProjectDiscovery en settings. |
| Dalfox no reconoce `url` | Probablemente hay una interfaz distinta. Usa una versión v2 revisada para esta integración o trabaja manualmente con la documentación de tu versión. |
| Cambios YAML no se aplican | Comprueba la raíz con el bloque siguiente (`BBHUNTER_HOME`, checkout o directorio actual) y si usas `-p NOMBRE`, que edita `programs/NOMBRE/scope.yaml`. |
| «program=... no coincide con el directorio» | El campo `program` de `programs/NOMBRE/scope.yaml` debe ser `NOMBRE`. |
| El panel responde «Host no permitido» u «Origen no permitido» | Ábrelo como `http://127.0.0.1:8000`. Otros nombres de host se rechazan para evitar DNS rebinding. |
| Error de sintaxis YAML | Usa espacios en vez de tabulaciones, conserva indentación y pon URLs/strings entre comillas. No dupliques claves. |

Puedes inspeccionar ajustes no sensibles sin mostrar claves:

```bash
python - <<'PY'
from bbhunter.config import ROOT, load_settings
from bbhunter.scope import load_scope
s, scope = load_settings(), load_scope()
print('Raiz:', ROOT)
print('Programa:', scope.program)
print('Simulacion:', s.dry_run, 'IA:', s.llm_enabled)
print('Base:', s.abs_db_path())
print('Informes:', s.abs_reports_dir())
PY
```

## Resultados vacíos o inesperados

| Síntoma | Interpretación y siguiente paso |
|---|---|
| «EN SCOPE» pero otra ruta no está permitida | El matcher solo mira host. Utiliza límites manuales de ruta/puerto y no el pipeline. |
| «Hosts vivos» sin respuesta verificable | Comprueba si falta httpx y si el activo tiene source `no-httpx` o `dry_run`. |
| Escaneo sin hallazgos | Ejecuta `bbhunter audit --failed`: si alguna herramienta falló o se omitió, el resultado está incompleto. Revisa también alcance, conectividad, autenticación y URLs de entrada. Ausencia de resultados no acredita seguridad. |
| Dalfox no aporta nada | Puede no haber URLs con query, fallar la interfaz/formato o no existir XSS. Revisa la URL exacta manualmente. |
| Hay hallazgos de ejemplo en real | Cambia a una base nueva y revisa qué activos venían de simulación; no los envíes. |
| Un resultado nuevo se considera duplicado | La clave local normaliza host/path y elimina query, esquema y puerto. Revisa manualmente; no elimina duplicados entre todas las plantillas ni refleja los del programa. |
| El equipo no reproduce | Repite desde cero con sesión limpia, cuenta/rol correctos, endpoint real y datos propios. Añade las precondiciones que faltan. |

## PDF, redacción y panel

Para añadir soporte PDF de hallazgos en Kali:

```bash
python -m pip install -e '.[pdf]'
python -m weasyprint --info
bbhunter report --id 3 --pdf
```

Si faltan bibliotecas del sistema, sigue el error y la documentación de WeasyPrint [S20]. Una instalación Python correcta no garantiza que estén todas las dependencias nativas. Comprueba que se creó el fichero PDF: un mensaje de finalización del pipeline puede coexistir con un fallo de exportación PDF.

Si el texto no usa IA, comprueba `llm_enabled`, disponibilidad del modelo y configuración de la clave sin imprimirla. Si un informe ya tiene explicación, `enrich` lo omite salvo `--force`. El fallback local también produce texto y no debe confundirse con una validación técnica.

Si el puerto 8000 está ocupado, usa `bbhunter dashboard --port 8001`. El botón de generar informe crea MD/HTML, no adjunta evidencias y no envía un reporte. El parámetro `?reported=1` del retorno del panel tampoco confirma un envío.

# 26. Lista previa al envío y rutina de trabajo

## Lista final: marcar solo después de comprobar

- [ ] La política vigente autoriza exactamente activo, técnica y tipo de vulnerabilidad.
- [ ] El activo es elegible para el canal de reporte elegido; si busco recompensa, revisé su elegibilidad específica.
- [ ] El resultado procede de una prueba real, no de `dry_run`, un ejemplo o una plantilla sin verificar.
- [ ] Reproduje desde una sesión nueva y documenté cuentas, roles y precondiciones.
- [ ] Tengo control positivo/negativo cuando ayuda a distinguir el fallo del comportamiento normal.
- [ ] Los pasos contienen el endpoint real, método y parámetro, sin depender de mi memoria.
- [ ] Petición, respuesta y capturas corresponden al mismo caso y a la misma fecha de validación.
- [ ] El impacto descrito está demostrado; las hipótesis quedan identificadas como tales.
- [ ] La severidad/vector se justifican por este caso, no solo por el valor de BBHunter.
- [ ] Redacté secretos y datos personales sin destruir la información necesaria para reproducir.
- [ ] Retiré placeholders, estimaciones de bounty y afirmaciones que la IA no puede acreditar.
- [ ] El título es concreto y el informe sigue la plantilla/campos que pide el programa.
- [ ] Los adjuntos están en el canal privado correcto y no en un enlace público.
- [ ] Revisé mi historial local para evitar reenvíos y agrupé la causa según la política.
- [ ] Guardé la versión final; después de enviar registraré el ID y la fecha.

## Rutina para una sesión manejable

Al comenzar, revisa cambios de política y el cuaderno. Escoge una función y un objetivo de investigación concreto. Actualiza el inventario únicamente con los datos que necesites; no lances todo el pipeline por costumbre.

Durante el análisis, guarda cada prueba con su control y decisión. Si cambias de cuenta, host, plantilla o técnica, vuelve a comprobar las restricciones aplicables. Si no aparece un fallo, anota qué cubriste y qué quedó pendiente.

Al terminar, detén panel, proxy o laboratorio que ya no necesites, guarda las evidencias privadas y registra siguiente paso. Si hay un caso confirmado, redacta mientras recuerdas las precondiciones y comprueba su reproducción antes del envío.

## Chuleta de BBHunter

```bash
bbhunter init                     # crear configuracion local
bbhunter init --program acme      # o un scope por programa en programs/acme/
bbhunter programs                 # programas configurados
bbhunter -p acme <comando>        # cualquier comando sobre ese programa
bbhunter scope-check URL          # host, puerto y ruta; codigo 1 si esta fuera
bbhunter recon                    # pasivo + sondeo HTTP (solo pasivo si allow_active_scan: false)
bbhunter scan                     # candidatos desde SQLite
bbhunter audit --failed           # fallos u omisiones: resultado incompleto
bbhunter list --status new        # candidatos por revisar
bbhunter enrich --id 3            # borrador local o API
bbhunter dashboard                # triaje local, sin editor
bbhunter set-status 3 validated   # tras reproducir
bbhunter set-status 3 ready       # tras revisar texto/adjuntos
bbhunter report --status ready --pdf
bbhunter set-status 3 reported    # despues del envio manual
```

Estos comandos no son una secuencia que debas copiar completa. Las fases activas solo se usan cuando encajan en la política y en las limitaciones explicadas en esta guía. Los IDs son ilustrativos.

# 27. Referencias y cómo aprender de otros reportes

## Referencias integradas en BBHunter

Los comandos `refs` descargan metadatos de un dataset comunitario de reportes divulgados y feeds RSS de Medium. No son un enlace oficial de sincronización con el programa que estás investigando, no leen sus reportes privados y no indican si tu caso es duplicado.

```bash
bbhunter refs sync --source hackerone
bbhunter refs sync --source medium
bbhunter refs stats
bbhunter refs search 'idor' --limit 5
bbhunter refs finding 3 --limit 5
```

Estas órdenes pueden contactar GitHub o Medium; no son parte del modo de simulación sin red. El dataset puede estar desactualizado y los RSS pueden fallar o devolver solo publicaciones recientes. Verifica el reporte original y su fecha. La «mediana» de recompensas es la mediana aritmética de los informes con bounty mayor que cero que aparecen en el resultado; es orientativa.

De un informe público aprende el orden de los pasos, las precondiciones y cómo conecta prueba con impacto. No copies su evidencia como si fuera tuya ni supongas que un bounty publicado fija el pago del programa actual.

## Fuentes oficiales consultadas

Consultadas el **24 de noviembre de 2026**. Las opciones de herramientas y formularios cambian; contrasta `--help`, versiones y política al iniciar cada trabajo. Los ejemplos y conclusiones del código local son elaboración para este proyecto, no citas textuales extensas de estas fuentes.

| ID | Fuente y uso en esta guía |
|---|---|
| S01 | [Kali: preparación de WSL](https://www.kali.org/docs/wsl/wsl-preparations/). Instalación de la distribución y elección de entorno. |
| S02 | [Go: instalación oficial](https://go.dev/doc/install). Requisitos de toolchain y PATH. |
| S03 | [Subfinder: instalación](https://docs.projectdiscovery.io/opensource/subfinder/install) y [repositorio oficial](https://github.com/projectdiscovery/subfinder). Interfaz y fuentes pasivas. |
| S04 | [httpx: uso y opciones](https://docs.projectdiscovery.io/opensource/httpx/usage). Límites, JSON y control de esquema/redirecciones. |
| S05 | [Nuclei: ejecución](https://docs.projectdiscovery.io/opensource/nuclei/running). Selección de plantillas, concurrencia y bloqueo Interactsh. |
| S06 | [Dalfox: repositorio oficial](https://github.com/hahwul/dalfox). Diferencia entre v2 en Go y v3 en Rust. |
| S07 | [Dalfox v2.11.0: flags](https://github.com/hahwul/dalfox/blob/v2.11.0/cmd/root.go) y [modo URL](https://github.com/hahwul/dalfox/blob/v2.11.0/cmd/url.go). Comando v2 y distinción JSON/JSONL. |
| S08 | [OWASP Juice Shop: ejecución](https://help.owasp-juice.shop/part1/running.html). Despliegue del laboratorio con Docker. |
| S09 | [OWASP WSTG v4.2](https://wstg.owasp.org/v4.2/). Marco de familias de pruebas web. |
| S10 | [Burp: primeros pasos](https://portswigger.net/burp/documentation/desktop/getting-started). Flujo inicial y navegador. |
| S11 | [Burp: definir el scope](https://portswigger.net/burp/documentation/desktop/getting-started/setting-target-scope). Inclusiones y exclusiones. |
| S12 | [Burp Repeater](https://portswigger.net/burp/documentation/desktop/getting-started/reissuing-http-requests). Repetir peticiones controladas. |
| S13 | [curl: manual oficial](https://curl.se/docs/manpage.html). Cabeceras, cuerpos, límites y codificación de parámetros. |
| S14 | [Naabu: opciones](https://docs.projectdiscovery.io/opensource/naabu/usage). TCP connect, puertos y unidades de tasa. |
| S15 | [FIRST: especificación CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document) y [calculadora](https://www.first.org/cvss/calculator/3.1). Métricas y vector. |
| S16 | [Bugcrowd VRT](https://bugcrowd.com/vulnerability-rating-taxonomy). Clasificación por tipo y variante. |
| S17 | [Anthropic: modelos disponibles](https://platform.claude.com/docs/en/models/overview). Comprobar IDs y disponibilidad antes de usar redacción API. |
| S18 | [HackerOne: envío de reportes](https://docs.hackerone.com/en/articles/8473994-submitting-reports). Formulario, contenido y adjuntos. |
| S19 | [Bugcrowd: informar un bug](https://docs.bugcrowd.com/researchers/reporting-managing-submissions/reporting-a-bug/). Target, VRT, reproducción y confidencialidad. |
| S20 | [WeasyPrint: primeros pasos e instalación](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html). Dependencias del exportador de hallazgos. |

# 28. Revisión del proyecto por fichero

Se revisaron los **35 ficheros versionados originales**, además de la estructura y procedencia de los datos locales y los seis informes generados existentes. `.git/`, `.venv/`, cachés y bibliotecas instaladas son infraestructura o dependencias, no código propio auditado. Se leyó el PDF anterior completo mediante extracción y se sustituyó por esta guía. No se inspeccionaron objetivos de ningún programa.

## Núcleo y comandos

| Fichero | Función y conclusión de revisión |
|---|---|
| `bbhunter/__init__.py` | Declara versión 0.1.0 y propósito. Sus afirmaciones generales sobre plataformas no sustituyen la política concreta. |
| `bbhunter/cli.py` | Define los comandos documentados y la opción global `--program/-p`. No acepta URL en run. Comprueba las reglas `allow_*` antes de la confirmación y bloquea las fases prohibidas (salida 2); la confirmación muestra límites de puerto/ruta/IP y la política de Nuclei. `scope-check` sale con 1 si el objetivo está fuera. Las operaciones por ID de la CLI no verifican siempre pertenencia al programa activo. |
| `bbhunter/config.py` | Carga settings; separa `RESOURCES` (dentro del paquete) de `ROOT` (`BBHUNTER_HOME`, checkout o directorio actual). Prioriza la variable de API. Usa ejemplos empaquetados como fallback. No valida límites positivos ni expande variables en los paths de herramientas. |
| `bbhunter/scope.py` | Patrones por host, wildcard, puerto, ruta (normalizada) e IP/CIDR, con exclusiones prioritarias; valida cada patrón al cargar. El wildcard no incluye el apex salvo regla explícita. No resuelve DNS. Incluye la política de Nuclei (`NucleiPolicy`, con validación contra inyección de argumentos) y la carga de `programs/NOMBRE/`. El mínimo de tasa es 1. |
| `bbhunter/tools.py` | Ejecuta binarios sin shell y con timeout. Procesa JSONL y omite líneas no válidas. `traffic_args()` añade cabeceras del programa y proxy a httpx, Nuclei y Dalfox (no a subfinder, que no contacta con el objetivo). |
| `bbhunter/recon.py` | Deriva semillas (dominios e IPs sueltas), enumera y sondea solo `host`, `host:puerto` o la URL de la ruta autorizada. Aplica los bloqueos `allow_*`. Sin httpx supone HTTPS; no recoge sistemáticamente endpoints con parámetros. |
| `bbhunter/scan.py` | Ejecuta Nuclei y Dalfox, clasifica y guarda candidatos. Respeta `allow_*`, registra cada ejecución y avisa si una herramienta falla; enmascara secretos en la evidencia antes de guardarla. Pasa a Nuclei la política del programa (allowlist, exclusiones, severidad, `-no-interactsh`) y lo omite con rutas sin allowlist. Dalfox solicita JSON y usa parser JSONL. |
| `bbhunter/db.py` | Persiste assets/findings y carga esquema refs en SQLite. Conserva datos entre sesiones; no cifra evidencia ni separa automáticamente demo de real. Consultas por ID no aplican filtro de programa. |
| `bbhunter/findings.py` | Deduplica con una clave corta de programa, clase, plantilla, host/path y parámetro. Omite esquema, puerto y query; convierte también path y parámetro a minúsculas. Puede unir casos distintos o separar una misma causa por plantilla. |
| `bbhunter/knowledge.py` | Clasifica etiquetas y calcula CVSS v3.1 desde vectores de la KB. La clase se asigna por heurística; fallo de cálculo devuelve 0.0. No confirma impacto real. |
| `bbhunter/enrich.py` | Rellena cuatro campos con plantillas o API. Omite los ya redactados salvo force. No conserva de forma completa la procedencia devuelta por el LLM. El ID explícito no verifica programa. |
| `bbhunter/llm.py` | Construye prompt, trunca evidencia a 3.000 caracteres y usa fallback ante errores. Enmascara la evidencia antes de enviarla (o la omite con `llm_evidence: none`) y la marca como datos no confiables. No garantiza precisión; su texto se revisa siempre. |
| `bbhunter/report.py` | Genera MD/HTML y PDF opcional. Exporta también no validados. El ID explícito prevalece sobre status/programa. Activa el autoescape para las plantillas HTML (incluida `report_html.j2`) y registra el filtro `nl2br`, que escapa antes de insertar saltos de línea. |
| `bbhunter/references.py` | Descarga dataset/RSS con límite de tamaño, filtra enlaces HTTPS y busca referencias. Medium admite dominios HTTPS externos; no garantiza confianza editorial. La disponibilidad de los feeds requiere cautela. |

## Panel y plantillas

| Fichero | Función y conclusión de revisión |
|---|---|
| `bbhunter/dashboard/__init__.py` | Inicializador vacío del paquete del panel; no añade controles. |
| `bbhunter/dashboard/app.py` | Rutas FastAPI de listado, detalle, estado e informe. Loopback por defecto, sin usuarios. Rechaza Host no local (DNS rebinding), exige token CSRF y Origin del mismo origen en los POST, envía CSP/`X-Frame-Options` y solo opera sobre hallazgos del programa activo. No hay editor ni adjuntos. |
| `bbhunter/dashboard/templates/base.html` | Diseño y navegación del panel. El aviso visual recuerda el triaje manual, pero no implementa controles de estado. |
| `bbhunter/dashboard/templates/index.html` | Filtros, contadores y tabla. «Ejecuta run» es una sugerencia del UI; no debe reemplazar la evaluación previa del alcance. |
| `bbhunter/dashboard/templates/finding.html` | Muestra evidencia, referencias y Markdown. Cambia estado y exporta MD/HTML con token CSRF; no redacta ni envía desde ese botón. |
| `bbhunter/resources/templates/report.md.j2` | Borrador con resumen, reproducción, evidencia e impacto. Incluye hueco para capturas y rangos orientativos de bounty que deben retirarse del envío. |
| `bbhunter/resources/templates/report_html.j2` | Presentación HTML/PDF del mismo contenido. Se renderiza con autoescape; los textos multilínea usan el filtro `nl2br`, que escapa antes de insertar `<br>`. |

## Configuración, conocimiento y scripts

| Fichero | Función y conclusión de revisión |
|---|---|
| `bbhunter/resources/config/scope.example.yaml` | Ejemplo, no permiso real. Documenta los formatos de patrón, `wildcard_includes_apex` y el bloque `nuclei:`. Sus booleanos iniciales true requieren revisión; las notas de política no se ejecutan. |
| `bbhunter/resources/config/settings.example.yaml` | Modelos, herramientas, límites, referencias y rutas. Incluye `audit_log`, `proxy`, `redact_evidence` y `llm_evidence`. No hay cookies de sesión para escáneres. La IA es opcional. |
| `bbhunter/resources/knowledge/vuln_kb.yaml` | Dos clases curadas y fallback. Los impactos son textos genéricos que deben ajustarse a la evidencia; no probar ni prometer robo de cookies/toma de cuenta por defecto. |
| `bbhunter/resources/knowledge/vrt_mapping.yaml` | Bandas CVSS, aproximación P1-P5 y pagos ilustrativos. No representa por completo VRT ni tablas de programas. |
| `scripts/install_tools.sh` | Instala Go tools con latest, actualiza plantillas y crea venv con extra pdf. PATH no persiste fuera del script; falta preparar libpcap-dev en algunos entornos. |
| `scripts/run_pipeline.sh` | Activa una venv Linux si existe y reenvía argumentos a run. No añade controles de alcance ni acepta un target adicional. |
| `pyproject.toml` | Declara Python >=3.11, dependencias, extras, entry point, `package-data` (plantillas, base de conocimiento y ejemplos viajan en el wheel) y configuración de ruff y pytest. No fija versiones de dependencias. |
| `.github/workflows/ci.yml` | En cada push y PR: ruff y pytest en Python 3.11–3.13, y un wheel instalado fuera del repo que ejecuta `init`, `programs`, `scope-check` y carga los recursos. |
| `.gitignore` | Excluye configuraciones, datos, informes, credenciales y cachés. No cifra ficheros ni evita compartirlos por otros medios. |

## Pruebas y documentación originales

| Fichero | Función y conclusión de revisión |
|---|---|
| `tests/test_scope.py` | Ocho pruebas de hosts, wildcard, exclusiones y tasa. Puerto, ruta, IP/CIDR y apex los cubre `tests/test_important.py`. |
| `tests/test_dedup.py` | Cinco pruebas de estabilidad, query, barras y parámetros. No evalúan colisiones semánticas por puerto/path sensible a mayúsculas. |
| `tests/test_report.py` | Cinco pruebas de clasificación, CVSS y presencia de secciones. No verifican PDF visual ni exactitud del impacto (el escape HTML lo cubre `test_gates.py`). |
| `tests/test_important.py` | 35 pruebas: patrones de puerto/ruta/IP y normalización, sondeo por patrón, política de Nuclei y su validación, protecciones del panel (Host, CSRF, Origin, programa), directorio por programa y recursos empaquetados. |
| `tests/test_references.py` | Siete pruebas offline de parseo, filtro, búsqueda y estadísticas. Incluye la mediana con un número par de recompensas. |
| `README.md` | Resumen operativo. Se enlaza esta guía y se aclaran alcance, simulación, validación y límites de la automatización. |
| `GUIA_BBHunter.pdf` | El original tenía siete páginas con instalación y flujo breve. Esta edición incorpora metodología, casos de scope, controles, informe, fuentes y revisión técnica. |

## Datos locales y salidas existentes al revisar

La base `data/bbhunter.sqlite` contenía seis activos, todos con `source=dry_run`, tres hallazgos y 10.045 referencias. Los hallazgos mostraban dos clases exposure y xss_reflected; uno tenía estado validated. Estos metadatos no convierten los ejemplos en descubrimientos reales. Se abrió la base en modo solo lectura para obtener recuentos y procedencia; no se sincronizó ni se alteró.

Se revisaron los seis documentos de ejemplo existentes en `reports/ejemplo-programa/`:

- `001-P2-fichero-env-expuesto.md` y `001-P2-fichero-env-expuesto.html`.
- `002-P2-repositorio-git-accesible.md` y `002-P2-repositorio-git-accesible.html`.
- `003-P3-reflected-xss-en-parametro-de-busqueda.md` y `003-P3-reflected-xss-en-parametro-de-busqueda.html`.

Coinciden con los ejemplos definidos por el código y carecen de validación real acreditada en esta revisión. No se borraron ni se sobrescribieron. Los informes reales deben ir en una base y carpeta nuevas con evidencia obtenida por ti dentro de un programa autorizado.

# 29. Verificación y mejoras pendientes

## Qué se comprobó en esta revisión

1. Lectura del código propio, tests, YAML, scripts, plantillas y documentación versionada; lectura de salidas de ejemplo y metadatos locales.
2. Ejecución de `python -m pytest -q` en la venv Windows existente: **84 pruebas superadas**, incluidas las de `tests/test_gates.py`, `tests/test_essentials.py` y `tests/test_important.py`. `ruff check .` sin avisos. No requieren escanear objetivos.
3. Comprobaciones adicionales en memoria: en la revisión inicial el wildcard incluía el apex y una URL con otro path o puerto se aceptaba. Tras la corrección se rechazan, y además se construyó el wheel y se ejecutó desde un directorio fuera del repositorio.
4. Simulación con mocks de herramientas: en la revisión inicial httpx y Dalfox se llamaban aunque ambos permisos estuvieran en false. Tras la corrección no se llama a ninguna herramienta con `allow_automated_tools: false`, y con `allow_active_scan: false` solo se llama a subfinder (`test_gates.py`). No se ejecutaron binarios reales ni se contactó con objetivos.
5. Renderizado HTML en memoria con un marcador `<script>`: en la revisión inicial la cadena quedaba sin escapar. Tras la corrección se escapa, y `test_gates.py` lo comprueba.
6. Consulta de documentación oficial para opciones de herramientas, taxonomías y formularios. Los comandos de investigación se han redactado a partir de esas interfaces y del código, sin probarlos contra programas reales.
7. Recorrido de simulación aislado con SQLite en memoria, IA desactivada y llamadas de red/binarios bloqueadas: un activo, tres candidatos, enriquecimiento local y tres pares MD/HTML generados correctamente en una carpeta temporal.
8. Comprobación de sintaxis de 42 bloques Bash, dos fragmentos Python embebidos y cinco bloques YAML. Verificación de los 29 marcadores del PDF, texto extraíble sin caracteres de sustitución e igualdad de la copia de la raíz.

La instalación completa en Kali, el comportamiento de versiones futuras de escáneres, la validez de un hallazgo real y la aceptación por una plataforma no se han verificado aquí. La documentación distingue esas limitaciones de las pruebas locales que sí se realizaron.

## Prioridades de desarrollo identificadas

| Prioridad | Cambio que haría falta implementar y probar |
|---|---|
| Antes de scope por URL muy estricto | Política de redirecciones en cada herramienta (hoy se filtran URLs y resultados, no cada petición). |
| Antes de escaneo restringido por programa | Sesiones por objetivo y limitador de tráfico compartido entre herramientas. |
| Antes de depender de Dalfox integrado | Alinear versión/comando y JSONL, comprobar esquema de salida, exigir control de permisos y concurrencia. |
| Para triaje fiable entre programas | Aislar también en la CLI las operaciones por ID al programa activo (el panel ya lo hace). |
| Para exportación y evidencias completas | Permitir edición y adjuntos, revisar puntuación específica y deduplicación. |
| Para distribución reproducible | Fijar versiones de dependencias y verificar instalación limpia en Kali (el wheel ya incluye los recursos y lo prueba el CI). |

Estas son conclusiones de análisis y trabajo futuro.

## Correcciones ya aplicadas en el código

| Problema detectado | Corrección |
|---|---|
| Las reglas `allow_*` solo avisaban. | `Scope.check_phase()` bloquea en `recon`, `scan` y `run`, y también dentro de los módulos, aunque se use `--yes`. `allow_automated_tools: false` bloquea todas las fases con herramientas; `allow_active_scan: false` bloquea el escaneo y deja el recon en pasivo. `dry_run` sigue funcionando porque no contacta con objetivos. |
| El informe HTML no escapaba la evidencia. | Autoescape activo en `report_html.j2` y filtro `nl2br` seguro. |
| La «mediana» de bounties tomaba el valor central superior. | Mediana aritmética real. |
| Un fallo de herramienta se veía como «0 hallazgos». | `audit.py`: cada ejecución se registra con código de salida y error; los fallos se muestran como «FALLO» y la fase como «RESULTADO INCOMPLETO». `bbhunter audit --failed` los lista. |
| No había registro de actividad. | `data/audit.jsonl`: fecha, fase, herramienta, comando (enmascarado), objetivos, límite de peticiones, código, duración y final del error. |
| Secretos del objetivo en claro en BD, informes y API. | `redact.py`: se enmascaran al guardar (`redact_evidence`) y otra vez antes de enviar a Claude; `llm_evidence: none` no envía evidencia. |
| Sin cabeceras de identificación ni proxy. | `request_headers` en el scope y `proxy` en settings, validados contra saltos de línea, para httpx, Nuclei y Dalfox. |
| El scope solo comparaba el hostname y el wildcard incluía el apex. | Patrones con puerto, ruta e IP/CIDR; `wildcard_includes_apex` (por defecto false); recon que sondea solo lo autorizado. |
| Nuclei usaba todas las plantillas y callbacks OAST. | Bloque `nuclei:` por programa: allowlist, `exclude_tags` (dos, fuzz, intrusive, bruteforce por defecto), severidades y `-no-interactsh`. Con rutas, Nuclei exige allowlist. |
| El panel aceptaba POST de cualquier web y cualquier Host. | Host local obligatorio, token CSRF, mismo origen, CSP y acciones limitadas al programa activo. |
| Un solo scope global. | `programs/NOMBRE/`, `bbhunter init --program`, `bbhunter programs` y `-p NOMBRE`. |
| Recursos fuera del paquete; sin CI. | Plantillas, base de conocimiento y ejemplos en `bbhunter/resources/`; CI con ruff, pytest y prueba del wheel. |

Estos cambios los cubren `tests/test_gates.py`, `tests/test_essentials.py` y `tests/test_important.py` (herramientas simuladas, sin red ni binarios).

## Regenerar esta guía

La fuente editable está en `docs/GUIA_BBHunter.md`. El generador no llama a escáneres ni a APIs. En un entorno con Python y ReportLab:

```bash
python -m pip install reportlab
python scripts/build_guide.py
```

Escribe `output/pdf/GUIA_BBHunter.pdf` y actualiza la copia de la raíz. Para revisar visualmente con Poppler:

```bash
mkdir -p tmp/pdfs
pdftoppm -r 90 -png output/pdf/GUIA_BBHunter.pdf tmp/pdfs/guia
pdfinfo output/pdf/GUIA_BBHunter.pdf
```

Comprueba en las imágenes que las tablas, comandos, acentos, cabeceras y números de página se leen sin recortes. La calidad final de un informe de vulnerabilidad requiere además repetir su prueba real y revisar su evidencia; regenerar un PDF solo verifica presentación.
