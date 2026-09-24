# PF07 - Interfaz visual y exploración forense

## 1. Objetivo

Validar que el MVP presenta los resultados del análisis mediante una interfaz visual que permita consultar procesos priorizados, explorar relaciones del grafo e inspeccionar las evidencias individuales, multi-plugin y relacionales utilizadas por los modelos A, B y C.

También se verifica la separación entre modo analista y modo evaluación y la disponibilidad de resultados en formatos estándar.

## 2. Componentes evaluados

Se revisaron:

- `src/mvp/build_dashboard.py`
- `src/mvp/visualize_graph.py`
- `src/mvp/process_inspector.js`
- `src/mvp/build_process_graph.py`

Artefactos principales:

- `data/output/dashboard/index.html`
- `process_graph.json`
- `focus_graph.json`
- `graph_summary.json`
- `process_graph.graphml`
- `graph_A.html`
- `graph_B.html`
- `graph_C.html`
- `graph_A_evaluation.html`
- `graph_B_evaluation.html`
- `graph_C_evaluation.html`

## 3. Dashboard

El dashboard permite seleccionar:

- muestra
- modelo A, B o C
- modo Analista o Evaluación

Se muestran indicadores de:

- número de procesos
- número de relaciones
- procesos con actividad de red
- procesos con evidencia malfind
- procesos psscan-only

También contiene un listado Top-10 de procesos priorizados.

## 4. Priorización

Cada modelo muestra su propio Top-10.

La interfaz consume los rankings ya calculados por el pipeline y no vuelve a calcular los anomaly scores ni las posiciones.

Por tanto, el dashboard funciona como capa de presentación de los artefactos analíticos previamente generados.

## 5. Exploración del grafo

La visualización utiliza un grafo dirigido de procesos.

Las aristas representan relaciones:

`padre -> hijo`

Los nodos Top-N se utilizan como semillas y se expande su contexto mediante relaciones de parentesco.

La visualización permite:

- zoom
- desplazamiento
- navegación
- selección de nodos
- inspección de contexto
- visualización de padres e hijos

## 6. Inspector de procesos

Al seleccionar un proceso se muestran sus datos de identidad y priorización.

### Priorización

Se presentan:

- rank A
- anomaly score A
- rank B
- anomaly score B
- rank C
- anomaly score C

### Evidencia individual

Se presentan, entre otros:

- threads
- WOW64
- create_time
- exit_time
- duración del proceso

### Evidencia multi-plugin

Se presentan:

- pslist
- psscan
- longitud de cmdline
- regiones malfind
- regiones RWX
- malfind total commit charge
- objetos de red
- TCP
- UDP
- IPs remotas únicas
- IPs públicas

### Evidencia relacional

Se presentan:

- padre
- hijos
- parent_resolved
- child_count
- resolved_ancestor_count
- parent_has_network
- parent_has_malfind
- parent_psscan_only
- children_with_network_count
- children_with_malfind_count
- children_psscan_only_count

## 7. Identidad

La selección entre dashboard y grafo utiliza prioritariamente `process_uid`.

El PID se utiliza únicamente como mecanismo alternativo cuando puede resolverse de forma inequívoca.

Esto reduce el riesgo derivado de reutilización de PID dentro de una muestra.

## 8. Separación entre modo Analista y Evaluación

Se verificaron los archivos:

- `graph_B.html`
- `graph_B_evaluation.html`

Para Cusdaem.exe se obtuvo:

- ANALYST has Cusdaem = True
- EVALUATION has Cusdaem = True
- ANALYST exposes Ground truth = False
- EVALUATION exposes Ground truth = True

Por tanto, el proceso y sus evidencias siguen disponibles para el análisis, pero el ground truth solo se muestra explícitamente durante la evaluación del dataset.

## 9. Caso funcional: Cusdaem.exe

Muestra:

`win10dump5`

Identidad:

- process_uid: `proc_a034eff74e65acf3`
- PID: 3628
- PPID: 6728
- image_name: Cusdaem.exe
- ground truth: Malicious

Priorización:

- A: rank 5
- B: rank 2
- C: rank 2

Scores:

- A: 0.675768751883159
- B: 0.692628626135264
- C: 0.649093150300993

Evidencia multi-plugin:

- cmdline_length: 38
- malfind_region_count: 4
- malfind_rwx_count: 4
- malfind_total_commit_charge: 5
- network_object_count: 6
- tcp_object_count: 2
- udp_object_count: 4
- unique_remote_ip_count: 2
- public_remote_ip_count: 2

Contexto relacional:

- parent_resolved: 1
- padre: chrome.exe PID 6728
- child_count: 0
- resolved_ancestor_count: 4
- parent_has_network: 1
- parent_has_malfind: 0

La interfaz mostró correctamente estos valores.

La selección del proceso desde el Top-10 resaltó el nodo correspondiente y abrió su detalle en el inspector.

## 10. Métricas agregadas

En modo Evaluación se muestran métricas agregadas del modelo seleccionado.

Para el Modelo B se observaron:

- Mean first malicious rank: 11.000
- Mean MRR: 0.177
- Weighted mean malicious rank: 18.625
- Micro Recall@5: 0.250
- Micro Recall@10: 0.375

Estos valores coinciden con los resultados validados previamente en PF06.

## 11. Exportación

El pipeline genera resultados en formatos estándar, entre ellos:

- CSV
- JSON
- GraphML
- HTML

Ejemplos:

- `rank_A.csv`
- `rank_B.csv`
- `rank_C.csv`
- `evaluation_summary.csv`
- `aggregate_models.csv`
- `process_graph.json`
- `focus_graph.json`
- `graph_summary.json`
- `process_graph.graphml`

No existe actualmente un botón de descarga dentro del dashboard.

La exportación se realiza mediante los artefactos generados por el pipeline.

Esta característica se considera suficiente para el alcance del MVP, mientras que una descarga directa desde la interfaz puede considerarse una mejora futura de usabilidad.

## 12. Consideración sobre focus_graph

Existen dos mecanismos relacionados con el subgrafo focal:

1. `build_process_graph.py` genera `focus_graph.json`.
2. `visualize_graph.py` selecciona directamente desde `process_graph.json` los nodos Top-N y su contexto.

La interfaz utiliza el segundo mecanismo.

Esto no afecta la validez funcional, aunque supone duplicidad de lógica que podría consolidarse en futuras versiones.

## 13. Requisitos funcionales

### RF-09

El sistema genera y presenta un listado priorizado de procesos sospechosos.

**Resultado: PASS**

### RF-10

El sistema permite consultar y explorar relaciones entre procesos mediante el grafo dirigido y el inspector.

**Resultado: PASS**

### RF-11

El sistema presenta los resultados mediante una interfaz visual interactiva.

**Resultado: PASS**

### RF-12

El sistema genera resultados exportables en formatos estándar como CSV y JSON, además de GraphML y HTML.

**Resultado: PASS**

## 14. Resultado

**Resultado: PASS**

PF07 demuestra que los artefactos generados por el pipeline pueden ser inspeccionados mediante una interfaz visual consistente con los rankings, scores, características y relaciones previamente validados.

## 15. Conclusión

El dashboard completa el flujo funcional del MVP al transformar los artefactos analíticos en una herramienta de triage visual.

El usuario puede pasar de un listado priorizado a la inspección detallada de un proceso y posteriormente analizar su contexto relacional dentro del grafo.

La separación entre modo Analista y modo Evaluación evita revelar el ground truth durante la simulación del análisis forense real.

La prueba funcional sobre Cusdaem.exe confirmó la consistencia entre la interfaz y los artefactos originales del pipeline.
