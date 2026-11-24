# [Clase de vulnerabilidad] en [función/endpoint] permite [efecto demostrado]

<!-- Sustituye todos los campos. No envíes ejemplos ni afirmaciones no probadas. -->

## Resumen

[Qué permite el fallo, con qué rol y qué límite de seguridad rompe. 2-4 frases.]

## Activo y alcance

- Programa y plataforma: [nombre]
- Política consultada: [enlace oficial y fecha]
- Activo elegible: [entrada exacta del programa]
- URL/endpoint y método: [URL completa + método]
- Parámetro/objeto: [ubicación exacta]
- Fecha de última reproducción: [AAAA-MM-DD HH:MM UTC]

## Precondiciones

- [Cuentas de prueba y rol, sin publicar credenciales]
- [Pertenencia o separación de organizaciones; permisos esperados]
- [Objeto sintético y privacidad; cómo crearlo desde cero]
- [Interacción de usuario o estado de sesión necesarios]

## Pasos para reproducir

1. [Entrar con la cuenta/rol correcto y preparar el dato propio.]
2. [Hacer la acción normal y guardar la petición/respuesta de control.]
3. [Cambiar únicamente el dato o permiso relevante.]
4. [Enviar la petición y observar el efecto preciso.]
5. [Repetir desde una sesión limpia si es relevante.]

## Resultado esperado

[Qué debería permitir o denegar la aplicación y por qué.]

## Resultado observado

[Qué ocurrió realmente. Referencia el fragmento o adjunto que lo acredita.]

## Prueba de concepto

Petición de control redactada:

```http
[Petición real: método, path, host y cabeceras relevantes; sustituir secretos.]
```

Petición modificada redactada:

```http
[Petición real de la prueba, destacando el cambio.]
```

Respuesta o efecto relevante:

```text
[Estado, cabeceras relevantes y fragmento mínimo real de la respuesta.]
```

## Impacto y límites de la validación

- Confirmado: [consecuencia respaldada por evidencia]
- Precondiciones: [acceso, rol, interacción y conocimiento necesarios]
- Alcance observado: [objetos/cuentas propios revisados]
- No verificado: [extensiones o cadenas que no se probaron]

## Severidad propuesta

- [Taxonomía y variante que pida la plataforma]
- [CVSS y vector si corresponde; justificar métricas según este caso]
- [Explicación breve del impacto sin estimaciones ni exigencias de pago]

## Remediación sugerida

[Control concreto ligado a la causa; no una lista genérica de buenas prácticas.]

## Adjuntos privados

- [01-control.txt: qué muestra y con qué paso se corresponde]
- [02-prueba.txt: qué muestra]
- [03-resultado.png / vídeo corto: qué muestra]

## Limpieza y notas para el retest

[Datos sintéticos creados/eliminados, estado que debe restaurarse y forma mínima de retestar.]

## Referencias

[Solo fuentes relevantes para la causa o solución. No uses otros reportes como evidencia de este caso.]

<!-- Revisión final: alcance, reproducción limpia, impacto probado, secretos redactados,
     adjuntos privados, ausencia de placeholders y copia de la versión enviada. -->
