---
name: "prezentace"
description: "Stálý průvodce prezentační platformou v `c:\github\presentations`. Pomáhá autorům (mluvčím + organizátorům) navigovat celý ekosystém — od založení nového eventu, přes import externích slidů (Google Sl"
category: security
subcategory: security-misc
tags: []
relevance: 0
source: "https://github.com/Umelainteligence-cz/presentations/blob/e54762b8a7f3421d27de5d8746cb97311a1548f6/.claude/skills/prezentace/SKILL.md"
author: "Umelainteligence-cz"
license: "MIT"
---
# prezentace


## Description
Stálý průvodce prezentační platformou v `c:\github\presentations`. Pomáhá autorům (mluvčím + organizátorům) navigovat celý ekosystém — od založení nového eventu, přes import externích slidů (Google Slides PDF, Keynote, PowerPoint, PNG screenshoty), tvorbu/úpravu mega-deck prezentací, až po správu live mode, Q&A scope, speaker auth a brand konzistence. Skill je BRAND-AGNOSTIC — zná víc design themes (zatím jen UICZ Uměláinteligence.cz, další půjdou přidat jako `themes/<jméno>/`). Při aktivaci načte event-specific `config.json` field `theme`, vybere odpovídající theme pack z `references/themes/<theme>/`, pracuje v jeho brandu a layoutech. Aktivuj tenhle skill VŽDY když: pracuje se v `c:\github\presentations` nebo jakémkoli `events/<slug>/...`, je řeč o převodu externích slidů, někdo edituje `_partials/`, `index.html` mega-deck, `config.json`, `event.json` nebo `skill-context.json`, padají otázky o brand barvách/typografii/layoutech, padají otázky o reveal.js engine features (zen mode `Z`, Q&A overlay `Q`, speaker notes `D`, live mode, speaker auth `#k=<secret>`, semantic-hash routing), nebo padají české fráze typu „vytvoř slidy pro [jméno]", „naimportuj prezentaci [jméno]", „převést PDF/Keynote/Google Slides", „doplň mluvčího", „authorize do meetup decku", „chci zapracovat svou prezentaci", „mega-deck", „prezentace.umelainteligence.cz", „Renesance práce". Alternativní invocation: uživatel může napsat `/prezentace`, `/deck`, `/slidy`, „použij deck skill", „spusť prezentace skill" — všechny varianty aktivují tenhle skill (canonical name je `prezentace`, ostatní jsou aliases přes description matching). Aktivuj i když uživatel pouze otevírá session v tomhle repu a chce vědět kde stojí — skill při startu sám podá status a navrhne další krok.


## Source
https://github.com/Umelainteligence-cz/presentations/blob/e54762b8a7f3421d27de5d8746cb97311a1548f6/.claude/skills/prezentace/SKILL.md


## Relevance Score
0
