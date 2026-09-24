# PF06 - Evaluación del ranking contra ground truth

## 1. Objetivo

Validar que los rankings generados por los modelos A, B y C son evaluados correctamente contra el ground truth de XAI-DF y cuantificar el efecto de incorporar correlación multi-plugin y contexto relacional sobre la priorización de procesos maliciosos conocidos.

## 2. Separación entre detección y evaluación

El ground truth no participa en el entrenamiento de Isolation Forest.

El flujo evaluado es:

features -> Isolation Forest -> ranking -> ground truth -> métricas

Las etiquetas se adjuntan únicamente después de haber generado los rankings.

## 3. Construcción del ground truth

El mapeo utiliza:

- PID
- PPID
- Process_Name

Un proceso recibe una etiqueta Benign o Malicious únicamente cuando existe coincidencia exacta de identidad.

Cuando un PID no está presente en el ground truth:

- label_text = Unknown
- label_binary vacío
- mapping_status = not_in_ground_truth

Cuando PID coincide pero nombre o PPID no coinciden, la etiqueta no se fuerza y se utiliza:

- label_text = Unknown
- mapping_status = pid_match_identity_mismatch

## 4. Validación global del ground truth

Se validaron seis dumps.

| Muestra | Procesos | Benign | Malicious | Unknown |
|---|---:|---:|---:|---:|
| win10dump1 | 109 | 108 | 1 | 0 |
| win10dump2 | 104 | 95 | 1 | 8 |
| win10dump3 | 95 | 94 | 1 | 0 |
| win10dump4 | 94 | 92 | 2 | 0 |
| win10dump5 | 97 | 95 | 1 | 1 |
| win10dump6 | 83 | 78 | 2 | 3 |

Totales:

- Procesos: 582
- Benign: 562
- Malicious: 8
- Unknown: 12
- Mapeos exactos: 570
- Identity mismatches: 0

En todas las muestras se obtuvo:

- misma población entre process_master.csv y labels.csv
- 0 process_uid duplicados
- 0 errores de identidad
- 0 errores label_text/label_binary
- 0 Unknown con mapping_status exact

## 5. Caso de referencia

En win10dump5:

- PID: 3628
- PPID: 6728
- Proceso: Cusdaem.exe
- process_uid: proc_a034eff74e65acf3
- label_text: Malicious
- label_binary: 1
- mapping_status: exact

El proceso se encuentra en:

- Modelo A: rank 5
- Modelo B: rank 2
- Modelo C: rank 2

## 6. Métricas evaluadas

Por muestra se calculan:

- first_malicious_rank
- mean_malicious_rank
- reciprocal rank del primer proceso malicioso
- Recall@1
- Recall@3
- Recall@5
- Recall@10
- known_benign_before_first_malicious
- unknown_before_first_malicious

El campo denominado `mrr` en la evaluación individual corresponde al reciprocal rank de la muestra.

La media de esos reciprocal ranks entre dumps corresponde al Mean Reciprocal Rank (MRR).

## 7. Recomputation independiente

Las métricas de los seis dumps fueron recomputadas independientemente a partir de:

- rank_A.csv
- rank_B.csv
- rank_C.csv
- labels.csv

En todas las muestras se obtuvo:

- summary_errors = 0
- comparison_errors = 0

Esto valida los contenidos de:

- evaluation_summary.csv
- model_comparison.csv

## 8. Resultados individuales

### win10dump1

- A: first=2, RR=0.5
- B: first=4, RR=0.25
- C: first=4, RR=0.25

### win10dump2

- A: first=3, RR=0.333333
- B: first=12, RR=0.083333
- C: first=20, RR=0.05

### win10dump3

- A: first=10, RR=0.1
- B: first=15, RR=0.066667
- C: first=27, RR=0.037037

### win10dump4

Dos procesos Malicious.

- A: first=6, mean malicious rank=28
- B: first=25, mean malicious rank=48.5
- C: first=14, mean malicious rank=44

### win10dump5

- A: first=5, RR=0.2
- B: first=2, RR=0.5
- C: first=2, RR=0.5

### win10dump6

Dos procesos Malicious.

- A: first=1, mean malicious rank=1.5
- B: first=8, mean malicious rank=9.5
- C: first=6, mean malicious rank=10

## 9. Evaluación agregada por muestra

| Modelo | Mean first malicious rank | Mean malicious rank | MRR |
|---|---:|---:|---:|
| A | 4.500 | 9.875 | 0.383333 |
| B | 11.000 | 18.625 | 0.177500 |
| C | 12.166667 | 20.125 | 0.179189 |

### Micro Recall

| Modelo | R@1 | R@3 | R@5 | R@10 |
|---|---:|---:|---:|---:|
| A | 0.125 | 0.500 | 0.625 | 0.875 |
| B | 0.000 | 0.125 | 0.250 | 0.375 |
| C | 0.000 | 0.125 | 0.250 | 0.375 |

### Macro Recall

| Modelo | R@1 | R@3 | R@5 | R@10 |
|---|---:|---:|---:|---:|
| A | 0.083333 | 0.500000 | 0.666667 | 0.916667 |
| B | 0.000000 | 0.166667 | 0.333333 | 0.416667 |
| C | 0.000000 | 0.166667 | 0.333333 | 0.416667 |

## 10. Comparación por muestra

A -> B:

- improved: 1/6
- unchanged: 0/6
- worsened: 5/6
- mean rank delta: +6.5

B -> C:

- improved: 2/6
- unchanged: 2/6
- worsened: 2/6
- mean rank delta: +1.166667

A -> C:

- improved: 1/6
- unchanged: 0/6
- worsened: 5/6
- mean rank delta: +7.666667

Un delta negativo representa mejora y un delta positivo representa degradación.

## 11. Evaluación de los ocho procesos maliciosos

| Sample | Proceso | A | B | C |
|---|---|---:|---:|---:|
| win10dump1 | ButterflyOnDes | 2 | 4 | 4 |
| win10dump2 | Hexachlorocycl | 3 | 12 | 20 |
| win10dump3 | msedge.exe | 10 | 15 | 27 |
| win10dump4 | explorer.exe | 6 | 25 | 14 |
| win10dump4 | NisSrv.exe | 50 | 72 | 74 |
| win10dump5 | Cusdaem.exe | 5 | 2 | 2 |
| win10dump6 | OneDrive.exe | 1 | 8 | 14 |
| win10dump6 | kclglegrgq.exe | 2 | 11 | 6 |

Comparación por proceso:

A -> B:

- improved: 1
- unchanged: 0
- worsened: 7
- improvement rate: 0.125
- worsening rate: 0.875
- mean rank delta: +8.75

B -> C:

- improved: 2
- unchanged: 2
- worsened: 4
- improvement rate: 0.25
- worsening rate: 0.50
- mean rank delta: +1.5

A -> C:

- improved: 1
- unchanged: 0
- worsened: 7
- improvement rate: 0.125
- worsening rate: 0.875
- mean rank delta: +10.25

## 12. Consistencia cruzada de agregadores

Se compararon independientemente:

- aggregate_evaluation.py
- aggregate_malicious_processes.py

Se comprobó que:

- ambos contabilizan 8 procesos Malicious
- weighted_mean_malicious_rank coincide con mean_malicious_rank por proceso
- micro Recall@1/3/5/10 coincide con el Recall calculado directamente sobre los 8 procesos

Resultado:

`cross_aggregation_errors = 0`

Por tanto, ambas rutas de agregación son matemáticamente consistentes.

## 13. Interpretación experimental

En las seis muestras evaluadas, el Modelo A obtuvo mejores métricas agregadas de priorización que los modelos B y C.

La incorporación de correlación multi-plugin en B no produjo una mejora global en este conjunto de datos.

La incorporación posterior de contexto relacional en C produjo un comportamiento mixto respecto de B:

- algunos procesos y muestras mejoraron
- algunos permanecieron sin cambios
- otros empeoraron

Por tanto, los resultados no respaldan una mejora sistemática derivada exclusivamente del aumento de contexto.

Sin embargo, el contexto adicional sí modifica de forma mensurable la priorización.

Un ejemplo favorable es Cusdaem.exe:

`A=5 -> B=2 -> C=2`

Otro ejemplo muestra recuperación parcial mediante contexto relacional:

`explorer.exe: A=6 -> B=25 -> C=14`

## 14. Limitaciones

La evaluación está limitada al conjunto experimental disponible:

- 6 dumps Windows 10 XAI-DF
- 582 procesos evaluados
- 8 procesos Malicious conocidos

Los resultados describen este conjunto experimental y no deben generalizarse automáticamente a todas las imágenes de memoria Windows.

El ground truth se indexa inicialmente por PID y exige unicidad de PID dentro de cada hoja XAI-DF.

## 15. Resultado

**Resultado: PASS**

PF06 queda validado tanto a nivel individual por muestra como a nivel agregado.

Las métricas, comparaciones y agregaciones fueron verificadas mediante cálculos independientes y rutas de agregación diferentes.

## 16. Conclusión

El MVP permite evaluar de forma reproducible y trazable el efecto de añadir correlación multi-plugin y contexto relacional sobre la priorización de procesos sospechosos.

En el conjunto experimental evaluado, una mayor cantidad de contexto no implicó automáticamente mejores rankings, evidenciando la necesidad de analizar la relevancia y ponderación de las características incorporadas en futuras iteraciones.
