---
name: "rag-evaluator"
description: "Generates tailored giskard.checks evaluation suites for RAG (Retrieval-Augmented Generation) systems. Use whenever a user describes a Q&A bot grounded in documents, a knowledge-base chatbot, a retriev"
category: red-team
subcategory: red-team
tags: ["ai:rag"]
relevance: 1
source: "https://github.com/Giskard-AI/giskard-skills/blob/HEAD/oss/checks/rag-evaluator/SKILL.md"
author: "Giskard-AI"
license: "Apache-2.0"
---
# rag-evaluator


## Description
Generates tailored giskard.checks evaluation suites for RAG (Retrieval-Augmented Generation) systems. Use whenever a user describes a Q&A bot grounded in documents, a knowledge-base chatbot, a retrieval system, or wants to evaluate answer groundedness, faithfulness, hallucination, retrieval quality, citation accuracy, or out-of-scope handling. Triggers on phrases like "evaluate my RAG", "test my retrieval", "check groundedness", "build a RAG eval suite", "eval my chatbot answers from docs", "test if my agent hallucinates", "check if my answers are faithful to the sources", or any evaluation task involving an agent that answers from documents, FAQs, wikis, or a knowledge base. Use this skill even when the user does not explicitly say "RAG" but describes an agent grounded in documents. For adversarial / red-teaming evaluation, use the `scenario-generator` skill instead. This skill focuses on quality, not safety.


## Tags
ai:rag


## Source
https://github.com/Giskard-AI/giskard-skills/blob/HEAD/oss/checks/rag-evaluator/SKILL.md


## Relevance Score
1
