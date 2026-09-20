# Datos experimentales

Este directorio contiene localmente los datos utilizados por el pipeline
experimental de TFM Memory Forensics.

Los dumps de memoria, datasets originales y resultados generados no se
versionan en Git debido a su tamaño, naturaleza forense y condición de
artefactos reproducibles.

## Dataset

El experimento principal de la versión `v1.0.0` utiliza capturas de memoria
Windows 10 x64 pertenecientes al dataset XAI-DF.

Se utilizaron las siguientes muestras:

| Muestra | Archivo | Tamaño aproximado | SHA-256 |
| --- | --- | ---: | --- |
| win10dump1 | `Win10dump1.001` | 2 GB | `30294A897D0B265C4CEE30DF1EB94560FF8C562BE1F9A74469D3CBE12327CE7F` |
| win10dump2 | `Win10dump2.001` | 2 GB | `B732324B24754C6F9F22EB0EA830B1DCE12706D1F0BEDFD32930BEC563DB422F` |
| win10dump3 | `Win10dump3.001` | 2 GB | `2E06A8D80B137A4496CF4404131A5098B92294C69C6090D5149D919AE4A9579D` |
| win10dump4 | `Win10dump4.001` | 2 GB | `52638B6E209D125C7BB87F7543577C2F87C04653154E3DF9EE53F030C4B65FB7` |
| win10dump5 | `Win10dump5.001` | 2 GB | `366AB37E9742953027F95B43CCC73EC840E127D2AB272941786BC95629E6AD87` |
| win10dump6 | `Win10dump6.001` | 2 GB | `26ADB52BD90FA19E5EA346D9D95639D7E051B430DA9161E2CBB999DD4B88F5B8` |

Los hashes se utilizan para comprobar la integridad e identidad de las
muestras empleadas en el experimento.

## Ubicación local esperada

Los dumps utilizados durante el desarrollo se almacenan localmente en:

```text
data/
└── evidence/
    └── xai_df/
        └── windows10/
            ├── Win10dump1.001
            ├── Win10dump2.001
            ├── Win10dump3.001
            ├── Win10dump4.001
            ├── Win10dump5.001
            └── Win10dump6.001