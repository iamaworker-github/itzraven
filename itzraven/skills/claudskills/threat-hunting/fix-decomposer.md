---
name: "fix-decomposer"
description: "Descompone un fix grande en porciones atomicas cuando el cambio es demasiado amplio para resolverse de una sola vez. Usa esta skill SIEMPRE que la skill fix-developer detecte que un fix supera los cri"
category: threat-hunting
subcategory: threat-hunting
tags: []
relevance: 0
source: ""
author: ""
license: ""
---
# fix-decomposer


## Description
Descompone un fix grande en porciones atomicas cuando el cambio es demasiado amplio para resolverse de una sola vez. Usa esta skill SIEMPRE que la skill fix-developer detecte que un fix supera los criterios de complejidad, o cuando el usuario mencione descomponer un fix, dividir un fix en partes, crear porciones de fix, o fix grande. La skill advierte al desarrollador, descompone el fix en porciones Front/Back, incluye una porcion de verificacion de regresion, y guarda todo en una carpeta de documentacion del modulo afectado.


## Relevance Score
0
