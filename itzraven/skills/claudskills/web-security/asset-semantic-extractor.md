---
name: "asset-semantic-extractor"
description: "Sinh TOML semantic index cho ảnh/video raw để các skill phía sau map vào kịch bản. Ưu tiên đọc từ asset-index SQLite vector DB (mỗi file gọi Gemini đúng 1 lần trong toàn bộ project), chỉ fallback về p"
category: web-security
subcategory: web-security
tags: ["ai:gemini"]
relevance: 1
source: ""
author: ""
license: ""
---
# asset-semantic-extractor


## Description
Sinh TOML semantic index cho ảnh/video raw để các skill phía sau map vào kịch bản. Ưu tiên đọc từ asset-index SQLite vector DB (mỗi file gọi Gemini đúng 1 lần trong toàn bộ project), chỉ fallback về probe + vision pass tươi khi không có index.


## Tags
ai:gemini


## Relevance Score
1
