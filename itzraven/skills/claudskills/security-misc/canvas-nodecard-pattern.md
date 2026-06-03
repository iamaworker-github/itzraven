---
name: "canvas-nodecard-pattern"
description: "vibe-editor の Canvas モード (@xyflow/react) に新しいカード種 (CardType) や hand-off エッジを追加するときに使う skill。`src/renderer/src/stores/canvas.ts` の `CardType` ユニオン拡張、`CardData` 設計、zustand persist との整合、`CARD_TYPES` vali"
category: security
subcategory: security-misc
tags: []
relevance: 0
source: "https://github.com/yusei531642/vibe-editor/blob/HEAD/.claude/skills/canvas-nodecard-pattern/SKILL.md"
author: "yusei531642"
license: "MIT"
---
# canvas-nodecard-pattern


## Description
vibe-editor の Canvas モード (@xyflow/react) に新しいカード種 (CardType) や hand-off エッジを追加するときに使う skill。`src/renderer/src/stores/canvas.ts` の `CardType` ユニオン拡張、`CardData` 設計、zustand persist との整合、`CARD_TYPES` validator、`addCard` / `removeCard` の挙動 (cascadeTeam デフォルト、teamLocks, stageView)、Issue #157 (id 衝突 → crypto.randomUUID)、Issue #156 (pulseEdge TTL タイマ管理)、Canvas レンダリング側のコンポーネント追加箇所をカバー。ユーザーが「Canvas に◯◯カードを追加」「新しいノード種」「CardType を増やす」「@xyflow/react に新カスタムノード」「hand-off エッジ」「pulseEdge」「stageView」「teamLocks」「Canvas store を拡張」「ワークスペースプリセットに新カード」等を言ったとき、また `stores/canvas.ts` / `components/canvas/` / `layouts/CanvasLayout*` を編集しそうなときには必ずこの skill を起動すること。


## Source
https://github.com/yusei531642/vibe-editor/blob/HEAD/.claude/skills/canvas-nodecard-pattern/SKILL.md


## Relevance Score
0
