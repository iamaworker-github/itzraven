---
name: "craft-garnish"
description: "Garnish — Craft CMS's built-in JavaScript UI toolkit for the control panel. Covers the full Garnish surface: class system (Garnish.Base.extend, init, setSettings, addListener, on/off/trigger, destroy)"
category: threat-hunting
subcategory: threat-hunting
tags: ["lang:javascript", "type:integration"]
relevance: 0
source: ""
author: ""
license: ""
---
# craft-garnish


## Description
Garnish — Craft CMS's built-in JavaScript UI toolkit for the control panel. Covers the full Garnish surface: class system (Garnish.Base.extend, init, setSettings, addListener, on/off/trigger, destroy), UI widgets (Modal, HUD, DisclosureMenu, MenuBtn, CustomSelect, ContextMenu, Select), drag system (BaseDrag, DragSort, DragDrop, DragMove), form widgets (NiceText, CheckboxSelect, MixedInput, MultiFunctionBtn), utilities (key constants, ARIA helpers, focus management), and Craft integration (GarnishAsset, webpack externals, Craft.* class pattern). Triggers on: Garnish.Base.extend, Garnish.Modal, Garnish.HUD, Garnish.DragSort, Garnish.Select, Garnish.DisclosureMenu, Garnish.MenuBtn, Garnish.CustomSelect, addListener, removeListener, removeAllListeners, Garnish.ESC_KEY, Garnish.RETURN_KEY, activate event, textchange event, UiLayerManager, registerShortcut, trapFocusWithin, garnishjs, GarnishAsset, CpAsset, CP JavaScript, control panel JS, drag and drop, sortable, modal dialog, HUD popover, disclosure menu, menu button, Craft.CP, Craft.Slideout, Craft.ElementEditor, onSortChange, onOptionSelect, onSelectionChange, aria-modal, focus trap, keyboard navigation CP, this.base(), window.Garnish, expose-loader, CP memory leak, event listener cleanup, jQuery .on() in CP, selection interface, multi-select grid. Always use when writing, editing, or reviewing JavaScript that runs in the Craft CMS control panel — including plugin CP assets, custom field type JS, element index JS, CP webpack config, or code that imports garnishjs or references window.Garnish. Also trigger for Craft CP accessibility, keyboard interactions, drag-sort behavior, or CP JS memory issues. Do NOT trigger for front-end JavaScript (Alpine, Vue, htmx) or Twig templates.


## Tags
lang:javascript, type:integration


## Relevance Score
0
