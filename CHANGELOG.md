# Changelog

Todos los cambios relevantes del proyecto se documentarán en este archivo.

El formato sigue una estructura inspirada en Keep a Changelog y el proyecto
utiliza versionado semántico para identificar versiones congeladas del MVP.

## [1.0.0] - 2026-09-19

### Added

- Pipeline proceso-céntrico para análisis de memoria volátil.
- Integración con evidencia generada mediante Volatility 3.
- Normalización de procesos a partir de `pslist` y `psscan`.
- Construcción de tres espacios de características:
  - Modelo A: características individuales.
  - Modelo B: evidencia correlacionada multi-plugin.
  - Modelo C: contexto relacional padre-hijo.
- Detección de anomalías mediante Isolation Forest.
- Generación de rankings independientes para los modelos A, B y C.
- Separación física entre features del detector y ground truth.
- Evaluación mediante:
  - Recall@1
  - Recall@3
  - Recall@5
  - Recall@10
  - Mean Reciprocal Rank (MRR)
  - posición del primer proceso malicioso
  - posición media de procesos maliciosos
  - métricas macro y micro
- Evaluación agregada de procesos maliciosos.
- Construcción de grafos relacionales padre-hijo mediante NetworkX.
- Visualización interactiva de grafos mediante PyVis.
- Dashboard interactivo con:
  - selección de muestra;
  - selección de modelo A/B/C;
  - modo Analista;
  - modo Evaluación;
  - Top 10 interactivo;
  - detalle persistente del proceso;
  - comparación de ranks y scores A/B/C;
  - visualización de evidencia individual, multi-plugin y relacional;
  - navegación entre procesos del ranking y nodos del grafo.
- Resaltado de contexto relacional del proceso seleccionado.
- Visualización diferenciada de procesos `psscan-only`.
- Ground truth visible únicamente en modo Evaluación.
- Compatibilidad validada con seis dumps Windows 10 x64 del dataset XAI-DF.
- Documentación inicial para:
  - estructura de datos;
  - integridad de muestras;
  - dependencias;
  - herramientas externas.

### Experimental scope

La versión `1.0.0` corresponde al experimento principal congelado del TFM.

Incluye:

- 6 dumps de memoria;
- 582 procesos;
- 8 procesos maliciosos conocidos;
- 3 modelos experimentales;
- 5 plugins principales de Volatility 3.

Los resultados metodológicos obtenidos con esta versión deben considerarse
congelados. Cualquier modificación posterior de features, detector,
hiperparámetros o estrategia de evaluación deberá tratarse como una nueva
versión o experimento.