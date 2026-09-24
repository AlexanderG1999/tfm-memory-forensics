# PF05 - Detección de anomalías con Isolation Forest

## 1. Objetivo

Validar que el MVP implementa correctamente un mecanismo no supervisado de detección de anomalías mediante Isolation Forest y que los modelos A, B y C son comparables, reproducibles y utilizan exclusivamente las features definidas para cada nivel de análisis.

## 2. Implementación evaluada

Componente principal:

`src/mvp/run_isolation_forest.py`

Pipeline:

`src/mvp/run_sample_pipeline.py`

El detector utiliza `IsolationForest` de scikit-learn.

## 3. Conjuntos de features

### Modelo A

Utiliza 4 características individuales:

- threads
- wow64
- has_exit_time
- process_duration_seconds

### Modelo B

Utiliza las 4 características del Modelo A más 10 características obtenidas mediante correlación multi-plugin:

- in_pslist
- in_psscan
- cmdline_length
- malfind_region_count
- malfind_rwx_count
- malfind_total_commit_charge
- tcp_object_count
- udp_object_count
- unique_remote_ip_count
- public_remote_ip_count

Total:

`14 features`

### Modelo C

Utiliza las 14 características del Modelo B más 9 características relacionales:

- parent_resolved
- child_count
- resolved_ancestor_count
- parent_has_malfind
- parent_has_network
- parent_psscan_only
- children_with_malfind_count
- children_with_network_count
- children_psscan_only_count

Total:

`23 features`

La relación entre modelos es:

`A ⊂ B ⊂ C`

## 4. Separación respecto al ground truth

El detector recibe únicamente los archivos:

- `features_A.csv`
- `features_B.csv`
- `features_C.csv`

El ground truth no se proporciona a `run_isolation_forest.py`.

Las etiquetas se utilizan posteriormente en `evaluate_rankings.py`.

Por tanto, el entrenamiento del detector es no supervisado.

## 5. Construcción de la matriz

Las columnas de identidad no forman parte de las features del modelo.

No se utilizan como variables predictoras:

- process_uid
- sample_id
- pid
- ppid
- image_name
- label_text
- label_binary

La construcción de la matriz rechaza:

- valores ausentes
- valores no numéricos
- NaN
- infinito positivo
- infinito negativo

No existe imputación silenciosa.

## 6. Configuración de Isolation Forest

Configuración validada:

- `n_estimators = 500`
- `max_samples = auto`
- `contamination = auto`
- `random_state = 42`
- `n_jobs = -1`

Versión de scikit-learn utilizada:

`1.9.1`

## 7. Definición del score

El detector obtiene:

`raw_score = IsolationForest.score_samples(X)`

En esta salida, un valor menor representa mayor anomalía.

El MVP transforma esta orientación mediante:

`anomaly_score = -raw_score`

Por tanto:

`mayor anomaly_score = mayor anomalía`

Los rankings se ordenan de forma descendente por `anomaly_score`.

En caso de empate se utiliza:

1. PID
2. process_uid

para mantener determinismo.

## 8. Validación global sobre seis dumps

Se validaron:

- win10dump1
- win10dump2
- win10dump3
- win10dump4
- win10dump5
- win10dump6

En todas las muestras se verificó:

- La población de procesos de A, B y C es idéntica.
- La población de rankings A, B y C es idéntica.
- No existen process_uid duplicados.
- Cada ranking contiene exactamente los procesos de su archivo de features.
- No existen scores no finitos.
- `anomaly_score = -raw_score`.
- Los ranks son consecutivos desde 1 hasta N.
- Los resultados están ordenados correctamente por anomaly_score.

Contadores obtenidos en todas las muestras:

- `feature_vs_rank_errors = 0`
- `duplicate_uid_errors = 0`
- `score_sign_errors = 0`
- `nonfinite_errors = 0`
- `rank_sequence_errors = 0`
- `ordering_errors = 0`

## 9. Poblaciones evaluadas

| Muestra | Modelo A | Modelo B | Modelo C |
|---|---:|---:|---:|
| win10dump1 | 109 | 109 | 109 |
| win10dump2 | 104 | 104 | 104 |
| win10dump3 | 95 | 95 | 95 |
| win10dump4 | 94 | 94 | 94 |
| win10dump5 | 97 | 97 | 97 |
| win10dump6 | 83 | 83 | 83 |

## 10. Reproducibilidad

Se volvió a ejecutar Isolation Forest sobre `win10dump5` utilizando exactamente las mismas features y configuración.

La segunda ejecución escribió los resultados en una ubicación independiente para no sobrescribir los artefactos originales.

Comparación SHA-256:

- `rank_A.csv`: idéntico
- `rank_B.csv`: idéntico
- `rank_C.csv`: idéntico

Los tres rankings regenerados son idénticos byte por byte a los originales.

## 11. Configuración normalizada

El SHA-256 completo de `run_config.json` difiere porque el archivo contiene las rutas de salida de cada ejecución.

La ejecución original utiliza:

`data/output/detection/isolation/win10dump5`

La ejecución de reproducibilidad utiliza:

`data/output/validation/PF05_reproducibility`

Al excluir exclusivamente los campos `runs.<modelo>.output`, ambas configuraciones resultaron exactamente iguales:

`CONFIG_NORMALIZED_EQUAL = True`

Se verificó la coincidencia de:

- algoritmo
- versión de scikit-learn
- parámetros del modelo
- definición de features
- número de procesos
- número de features
- definición del score

## 12. Resultado de la prueba

**Resultado: PASS**

PF05 demuestra que los tres modelos A/B/C son ejecutados sobre poblaciones equivalentes mediante un detector no supervisado, con configuración explícita y reproducible.

Los resultados generados pueden utilizarse posteriormente para evaluar cómo cambia la priorización al incorporar correlación multi-plugin y contexto relacional.

## 13. Conclusión

PF05 queda validado como mecanismo funcional y reproducible de detección de anomalías mediante Isolation Forest.

La separación entre detección y ground truth permite que la evaluación posterior mida el comportamiento del detector sin utilizar las etiquetas durante el entrenamiento.
