# TFM Memory Forensics

Sistema experimental para la priorización de procesos potencialmente
sospechosos a partir del análisis de memoria volátil de sistemas Windows,
utilizando Volatility 3, correlación multi-plugin, contexto relacional y
detección de anomalías mediante Isolation Forest.

El proyecto forma parte de un Trabajo Fin de Máster (TFM) orientado al
análisis forense de memoria y a la evaluación del efecto de incorporar
evidencia correlacionada y contexto relacional sobre la priorización de
procesos.

## Objetivo

El objetivo del MVP es comparar tres niveles de representación de un
proceso obtenido desde una captura de memoria:

- **Modelo A — Individual:** características propias del proceso.
- **Modelo B — Multi-plugin:** características individuales más evidencia
  correlacionada obtenida desde diferentes plugins de Volatility 3.
- **Modelo C — Relacional:** características del modelo B más contexto
  derivado de relaciones padre-hijo entre procesos.

Los tres modelos utilizan la misma configuración de Isolation Forest para
permitir una comparación controlada del efecto de incorporar nueva
evidencia.

El sistema genera un ranking de procesos según su nivel de anomalía. El
ground truth se utiliza únicamente durante la evaluación experimental y no
participa en el entrenamiento del modelo.

## Alcance actual

La versión `v1.0.0` del MVP ha sido validada sobre seis capturas de memoria
Windows 10 x64 pertenecientes al dataset XAI-DF.

El experimento principal comprende:

- 6 dumps de memoria.
- 582 procesos analizados.
- 8 procesos maliciosos conocidos.
- 3 modelos experimentales: A, B y C.
- 5 fuentes principales de evidencia de Volatility 3.

El alcance validado actualmente corresponde a Windows 10 x64. Otros
sistemas operativos o versiones de Windows requieren validación adicional.

## Plugins de Volatility 3

El MVP utiliza evidencia obtenida mediante:

- `windows.pslist`
- `windows.psscan`
- `windows.cmdline`
- `windows.malware.malfind`
- `windows.netscan`

Volatility 3 se utiliza como herramienta externa de análisis de memoria y
extracción de artefactos forenses. Los archivos JSON producidos por estos plugins constituyen la
entrada del pipeline analítico.

## Arquitectura general

```text
Dump de memoria
      |
      v
Volatility 3
      |
      +-- pslist
      +-- psscan
      +-- cmdline
      +-- malfind
      +-- netscan
      |
      v
Normalización proceso-céntrica
      |
      +-- Modelo A
      +-- Modelo B
      +-- Modelo C
      |
      v
Isolation Forest
      |
      v
Ranking de procesos
      |
      +-- Evaluación experimental
      |
      +-- Grafo relacional
      |
      v
Dashboard interactivo