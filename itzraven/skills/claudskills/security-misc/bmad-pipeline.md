---
name: "bmad-pipeline"
description: "Orchestriert den kompletten BMAD-Entwicklungszyklus als automatische Pipeline: bmad-create-story → bmad-testarch-atdd → bmad-dev-story → bmad-testarch-test-review → bmad-code-review → bmad-security-re"
category: security
subcategory: security-misc
tags: ["type:review"]
relevance: 0
source: ""
author: ""
license: ""
---
# bmad-pipeline


## Description
Orchestriert den kompletten BMAD-Entwicklungszyklus als automatische Pipeline: bmad-create-story → bmad-testarch-atdd → bmad-dev-story → bmad-testarch-test-review → bmad-code-review → bmad-security-review (Kassandra, conditional), jeweils in frischem Kontext. Führt git add nach dev-story aus. Der Code-Review-Skill fixt Minor Issues selbst ("fixe minor issues instantly"). Pausiert nur bei Major/Critical Issues (User-Entscheidung), am Epic-Ende zwingend mit Kassandra-Security-Review und danach für die Retrospektive (liest sprint-status.yaml). Trigger: "bmad pipeline", "bmad run", "bmad start", "story pipeline", "neues feature", "story durchlaufen", "pipeline starten", immer wenn der User den kompletten BMAD-Flow starten will ohne jeden Schritt einzeln aufzurufen.


## Tags
type:review


## Relevance Score
0
