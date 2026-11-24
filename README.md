# NGINX2ROOT — análisis y laboratorio de seguridad

## Introducción

El 18 de noviembre de 2026 se divulgaron públicamente cinco vulnerabilidades
de seguridad que afectan a NGINX, identificadas conjuntamente bajo el nombre
**NGINX2ROOT**.

Estas vulnerabilidades fueron descubiertas por el equipo de investigación de
seguridad de **Xint** y están relacionadas con errores en la administración
de memoria durante el procesamiento de diferentes protocolos y servicios
implementados por NGINX.

Las vulnerabilidades se identifican como:

- **CVE-2026-123007:** procesamiento y control de flujo de HTTP/2.
- **CVE-2026-123633:** procesamiento de HTTP/2 en configuraciones de proxy inverso.
- **CVE-2026-123634:** resolución dinámica de nombres DNS.
- **CVE-2026-121810:** procesamiento de HTTP/3 en configuraciones de proxy inverso.
- **CVE-2026-113425:** procesamiento de la autenticación en el proxy de correo.

En determinadas condiciones, estas vulnerabilidades pueden permitir que un
atacante no autenticado consiga ejecutar código con los privilegios del
proceso trabajador de NGINX.

En este laboratorio vamos a centrarnos principalmente en la vulnerabilidad
**CVE-2026-123007**, que afecta al mecanismo de control de flujo del protocolo
HTTP/2 y está presente desde la versión 1.9.5 de NGINX, publicada en 2015.

### Herramientas y referencias del laboratorio

Para desarrollar nuestras experiencias utilizaremos como punto de partida
el trabajo realizado por los investigadores del equipo **Censys ARC
(Adversary Research and Countermeasures)**.

Este equipo desarrolló y publicó un conjunto de herramientas, pruebas de
concepto y capturas de tráfico obtenidas mediante experimentación en
entornos aislados.

Su trabajo permite estudiar el comportamiento de las vulnerabilidades,
comparar versiones afectadas y corregidas, y analizar las evidencias
obtenidas durante las pruebas.

El objetivo de nuestro laboratorio será comprender el funcionamiento de
la vulnerabilidad, reproducir experimentalmente el comportamiento del
servidor y analizar sus implicaciones desde la perspectiva de la seguridad
y la administración de sistemas GNU/Linux.

**Investigación original de Xint:**

https://nginx2root.com/

**Artículo técnico de Censys:**

[nginx2root: A simple test for the HTTP/2 flaw and three use-after-free reproductions](https://censys.com/blog/nginx2root-simple-test/)

**Repositorio desarrollado por Censys Research:**

https://github.com/Censys-Research/nginx2root