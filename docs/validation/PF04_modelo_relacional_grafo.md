# PF04 - Modelo relacional basado en grafo

## 1. Objetivo

Validar que el MVP construye de forma consistente un modelo relacional dirigido de procesos a partir de `process_master.csv`, utilizando relaciones padre-hijo resueltas mediante PID, PPID, identidad de proceso y validez temporal.

El grafo debe preservar los procesos normalizados, representar correctamente las relaciones padre-hijo y proporcionar features relacionales utilizables posteriormente por el modelo de detección de anomalías con contexto.

## 2. Implementación evaluada

Los componentes principales evaluados son:

- `src/mvp/build_features.py`
- `src/mvp/build_process_graph.py`

La resolución padre-hijo se realiza previamente en `build_features.py`.

El grafo se construye posteriormente utilizando `process_uid` como identificador único de nodo.

## 3. Resolución padre-hijo

Para un proceso hijo se buscan candidatos cuyo PID coincida con su PPID.

Se descartan:

- PPID igual a 0.
- PPID igual al PID del propio proceso.
- La misma entidad identificada mediante `process_uid`.
- Candidatos temporalmente incompatibles.

Una relación padre-hijo se considera temporalmente válida cuando:

`parent.CreateTime <= child.CreateTime`

y además:

`parent.ExitTime` es vacío

o:

`parent.ExitTime >= child.CreateTime`

Cuando existen varios candidatos válidos para un PPID, se selecciona el proceso válido con `CreateTime` más reciente.

## 4. Identidad relacional

Cada relación resuelta almacena:

- `parent_resolved`
- `parent_process_uid`
- `parent_pid_resolved`
- `parent_name`

La relación se basa finalmente en `process_uid`, evitando utilizar únicamente PID como identidad global.

## 5. Features relacionales

El MVP calcula para cada proceso:

- `parent_resolved`
- `child_count`
- `resolved_ancestor_count`
- `parent_has_malfind`
- `parent_has_network`
- `parent_psscan_only`
- `children_with_malfind_count`
- `children_with_network_count`
- `children_psscan_only_count`

Estas features proporcionan contexto relacional al Modelo C.

## 6. Construcción del grafo

`build_process_graph.py` utiliza un `networkx.DiGraph`.

Cada fila de `process_master.csv` se transforma en un nodo identificado mediante:

`process_uid`

Las relaciones padre-hijo se representan mediante aristas dirigidas:

`PADRE -> HIJO`

Cada arista contiene:

- `relation = parent_child`
- `source_type = PPID`
- `temporally_validated = 1`

La arista solamente se genera cuando:

- `parent_resolved = 1`
- existe `parent_process_uid`
- el nodo padre pertenece al grafo

## 7. Artefactos generados

El módulo genera:

- `process_graph.json`
- `focus_graph.json`
- `graph_summary.json`
- `process_graph.graphml`

El grafo JSON se representa como dirigido e incluye nodos y aristas.

## 8. Caso de prueba principal

Muestra:

`XAI_WIN10_DUMP05`

Proceso hijo:

- PID: 3628
- ImageFileName: `Cusdaem.exe`
- process_uid: `proc_a034eff74e65acf3`
- PPID: 6728

Padre resuelto:

- PID: 6728
- ImageFileName: `chrome.exe`
- process_uid: `proc_d46320fa71f74f2d`

La relación generada es:

`proc_d46320fa71f74f2d -> proc_a034eff74e65acf3`

Metadatos:

- `relation = parent_child`
- `source_type = PPID`
- `temporally_validated = 1`

Para `Cusdaem.exe`:

- `parent_resolved = 1`
- `resolved_ancestor_count = 4`
- `parent_has_malfind = 0`
- `parent_has_network = 1`
- `parent_psscan_only = 0`

Para su padre `chrome.exe`:

- `child_count = 12`
- `children_with_malfind_count = 1`
- `children_with_network_count = 2`
- `children_psscan_only_count = 0`

## 9. Validación estructural global

Se validaron los seis dumps procesados.

Resultados:

| Muestra | Nodos | Aristas | Padres resueltos | DAG |
|---|---:|---:|---:|---|
| win10dump1 | 109 | 95 | 95 | Sí |
| win10dump2 | 104 | 93 | 93 | Sí |
| win10dump3 | 95 | 87 | 87 | Sí |
| win10dump4 | 94 | 86 | 86 | Sí |
| win10dump5 | 97 | 86 | 86 | Sí |
| win10dump6 | 83 | 76 | 76 | Sí |

En las seis muestras se obtuvo:

- `missing_nodes = 0`
- `extra_nodes = 0`
- `missing_edges = 0`
- `extra_edges = 0`
- `orphan_edges = 0`
- `self_loops = 0`
- `multi_parent_nodes = 0`
- `child_count_errors = 0`
- `ancestor_count_errors = 0`

Todos los grafos evaluados son DAG.

## 10. Validación semántica global

Para los seis dumps se comprobaron las features y relaciones derivadas.

En todas las muestras se obtuvo:

- `parent_feature_errors = 0`
- `children_feature_errors = 0`
- `parent_identity_errors = 0`
- `temporal_errors = 0`
- `edge_metadata_errors = 0`
- `node_feature_copy_errors = 0`

Esto demuestra que:

- Las features del padre corresponden al padre realmente resuelto.
- Las features agregadas de hijos corresponden a los hijos reales.
- La identidad almacenada del padre es correcta.
- Todas las relaciones generadas cumplen las restricciones temporales.
- Todas las aristas conservan los metadatos esperados.
- Las features relacionales de `process_master.csv` llegan correctamente al grafo.

## 11. Resultado de la prueba

**Resultado: PASS**

Se verificó que:

- Cada proceso del master se representa mediante un nodo.
- Las relaciones padre-hijo son consistentes.
- Las relaciones están temporalmente validadas.
- No existen aristas huérfanas.
- No existen autorrelaciones.
- Ningún proceso tiene más de un padre.
- Los seis grafos son acíclicos.
- `child_count` coincide con la topología real.
- `resolved_ancestor_count` coincide con los ancestros reales.
- Las features relacionales son consistentes con los procesos vecinos.
- La información relacional se conserva al construir los nodos del grafo.

## 12. Conclusión

PF04 queda validado como mecanismo funcional de modelado relacional basado en grafos.

El MVP transforma la representación proceso-céntrica obtenida durante la correlación multi-plugin en un grafo dirigido de procesos, incorporando relaciones padre-hijo temporalmente validadas y atributos contextuales que posteriormente pueden ser utilizados por el modelo de detección de anomalías relacional.
