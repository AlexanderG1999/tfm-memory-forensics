@'
# PF03 - Correlación multi-plugin

## 1. Objetivo

Validar que el MVP correlaciona de forma consistente los artefactos obtenidos mediante los plugins de Volatility 3:

- pslist
- psscan
- cmdline
- malfind
- netscan

La correlación debe producir una representación proceso-céntrica única en `process_master.csv`, manteniendo una identidad estable mediante `process_uid`.

## 2. Implementación evaluada

La correlación se encuentra implementada principalmente en:

`src/mvp/build_features.py`

El universo de procesos se construye a partir de `pslist` y `psscan`.

La identidad base utilizada para correlacionar ambas fuentes es:

`(PID, ImageFileName, CreateTime)`

El identificador `process_uid` se genera a partir de:

`sample_id | PID | ImageFileName | CreateTime`

y se representa mediante un SHA-256 truncado.

Los artefactos de `cmdline`, `malfind` y `netscan` se asocian posteriormente a las entidades del universo de procesos.

## 3. Caso de prueba principal

Muestra:

`XAI_WIN10_DUMP05`

Proceso analizado:

- PID: 3628
- PPID: 6728
- ImageFileName: `Cusdaem.exe`
- process_uid: `proc_a034eff74e65acf3`
- CreateTime UTC: `2024-05-14T06:18:12+00:00`

## 4. Evidencia por plugin

### 4.1 pslist

El PID 3628 aparece en `pslist` con:

- PID: 3628
- PPID: 6728
- ImageFileName: `Cusdaem.exe`
- ExitTime: vacío

Resultado correlacionado:

`in_pslist = 1`

### 4.2 psscan

El mismo proceso aparece en `psscan` con la misma identidad:

- PID: 3628
- PPID: 6728
- ImageFileName: `Cusdaem.exe`

Resultado correlacionado:

`in_psscan = 1`

### 4.3 cmdline

Línea de comandos obtenida:

`"C:\Users\Barb\Downloads\Cusdaem.exe"`

Longitud calculada:

`38`

Resultado correlacionado:

`cmdline_length = 38`

### 4.4 malfind

Se identificaron cuatro registros asociados a PID 3628.

Todos presentan:

`PAGE_EXECUTE_READWRITE`

CommitCharge de las regiones:

- 1
- 1
- 2
- 1

Resultados correlacionados:

- `malfind_region_count = 4`
- `malfind_rwx_count = 4`
- `malfind_total_commit_charge = 5`

### 4.5 netscan

Para PID 3628 se obtuvieron ocho filas de `netscan`.

El MVP utiliza `(PID, Offset)` como unidad de deduplicación.

Se identificaron seis objetos únicos:

- 4 objetos UDP
- 2 objetos TCP

Las dos conexiones TCP contienen las direcciones remotas:

- `185.196.10.99`
- `111.90.145.141`

Resultados correlacionados:

- `network_object_count = 6`
- `tcp_object_count = 2`
- `udp_object_count = 4`
- `unique_remote_ip_count = 2`
- `public_remote_ip_count = 2`

## 5. Resultado consolidado

La entidad generada en `process_master.csv` presenta:

| Campo | Valor |
|---|---:|
| process_uid | proc_a034eff74e65acf3 |
| sample_id | XAI_WIN10_DUMP05 |
| pid | 3628 |
| ppid | 6728 |
| image_name | Cusdaem.exe |
| in_pslist | 1 |
| in_psscan | 1 |
| cmdline_length | 38 |
| malfind_region_count | 4 |
| malfind_rwx_count | 4 |
| malfind_total_commit_charge | 5 |
| network_object_count | 6 |
| tcp_object_count | 2 |
| udp_object_count | 4 |
| unique_remote_ip_count | 2 |
| public_remote_ip_count | 2 |

## 6. Validación de unicidad de process_uid

Se comprobó la unicidad de `process_uid` en los seis dumps procesados:

| Muestra | Procesos | process_uid únicos |
|---|---:|---:|
| win10dump1 | 109 | 109 |
| win10dump2 | 104 | 104 |
| win10dump3 | 95 | 95 |
| win10dump4 | 94 | 94 |
| win10dump5 | 97 | 97 |
| win10dump6 | 83 | 83 |

No se identificaron identificadores duplicados dentro de las muestras procesadas.

Además, el PID 3628 aparece en otra muestra (`win10dump3`) asociado a otro proceso y genera un `process_uid` diferente, confirmando que la identidad no depende exclusivamente del PID.

## 7. Resolución de ambigüedades

La función `find_process_for_artifact()` aplica una resolución determinista basada en:

1. PID.
2. Nombre de proceso, cuando está disponible.
3. Intervalo temporal, cuando el artefacto dispone de `event_time`.
4. Proceso activo visible mediante `pslist`.
5. Instancia con `CreateTime` más reciente.
6. Primer candidato como último recurso.

En `netscan`, el campo `Created` permite realizar correlación temporal cuando existen varias instancias candidatas.

## 8. Limitación conocida

Los artefactos procedentes de `cmdline` y `malfind` no proporcionan actualmente un `event_time` utilizado por el MVP para resolver posibles reutilizaciones ambiguas de PID.

En estos casos se aplica la heurística determinista de `find_process_for_artifact()`.

Esta limitación no impide el cumplimiento del alcance definido para PF03.

## 9. Resultado de la prueba

**Resultado: PASS**

Se verificó que:

- `pslist` y `psscan` convergen en una misma entidad.
- Los procesos exclusivos de `psscan` están soportados por el diseño.
- `cmdline` se asocia al proceso correspondiente.
- Los registros 1:N de `malfind` se agregan correctamente.
- Los registros de `netscan` se deduplican mediante `(PID, Offset)`.
- Los objetos de red se asocian a `process_uid`.
- Un mismo PID en muestras diferentes no provoca colisiones.
- `process_uid` es único en los seis dumps evaluados.
- Los valores de `process_master.csv` son trazables hasta los JSON originales de Volatility 3.

## 10. Conclusión

PF03 queda validado como mecanismo funcional de correlación multi-plugin.

El MVP transforma los resultados independientes de Volatility 3 en una representación proceso-céntrica consolidada que posteriormente puede ser utilizada por los módulos de detección de anomalías y análisis relacional.
'@ | Set-Content `
    .\docs\validation\PF03_correlacion_multiplugin.md `
    -Encoding UTF8