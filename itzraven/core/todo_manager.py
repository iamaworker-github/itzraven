"""
Agent Todo Tool — dedicated task tracking for agents.

Strix v0.5.0 inspired: agents maintain an explicit todo list,
breaking down complex engagements into concrete steps.
Tasks track status, priority, dependencies, and results.

Architecture:
  - TodoManager: global registry of all todos across agents
  - TodoItem: individual task with metadata
  - Agents create/update/complete todos as they work
  - Orchestrator can inspect agent todos for progress reporting
"""

import time
import uuid
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

from itzraven.core.logger import get_logger

logger = get_logger()


class TodoStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    SKIPPED = "skipped"


class TodoPriority(Enum):
    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3
    INFO = 4


@dataclass
class TodoItem:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    description: str = ""
    status: TodoStatus = TodoStatus.PENDING
    priority: TodoPriority = TodoPriority.MEDIUM
    agent_name: str = ""
    category: str = ""
    target: str = ""
    depends_on: List[str] = field(default_factory=list)
    result: Optional[str] = None
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "description": self.description,
            "status": self.status.value,
            "priority": self.priority.name,
            "agent_name": self.agent_name,
            "category": self.category,
            "target": self.target,
            "depends_on": self.depends_on,
            "result": self.result,
            "error": self.error,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "completed_at": self.completed_at,
            "tags": self.tags,
        }


class TodoManager:
    def __init__(self):
        self._todos: Dict[str, TodoItem] = {}
        self._agent_todos: Dict[str, List[str]] = {}

    def create_todo(
        self,
        description: str,
        agent_name: str = "",
        category: str = "",
        target: str = "",
        priority: TodoPriority = TodoPriority.MEDIUM,
        depends_on: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
    ) -> TodoItem:
        todo = TodoItem(
            description=description,
            agent_name=agent_name,
            category=category,
            target=target,
            priority=priority,
            depends_on=depends_on or [],
            tags=tags or [],
        )
        self._todos[todo.id] = todo
        if agent_name:
            if agent_name not in self._agent_todos:
                self._agent_todos[agent_name] = []
            self._agent_todos[agent_name].append(todo.id)
        logger.debug(f"Todo created: [{todo.id}] {description[:60]} ({agent_name})")
        return todo

    def update_status(self, todo_id: str, status: TodoStatus, result: Optional[str] = None, error: Optional[str] = None) -> Optional[TodoItem]:
        todo = self._todos.get(todo_id)
        if not todo:
            logger.warning(f"Todo not found: {todo_id}")
            return None
        todo.status = status
        todo.updated_at = time.time()
        if status == TodoStatus.COMPLETED:
            todo.completed_at = time.time()
        if result:
            todo.result = result
        if error:
            todo.error = error
        logger.debug(f"Todo updated: [{todo_id}] → {status.value}")
        return todo

    def get_todo(self, todo_id: str) -> Optional[TodoItem]:
        return self._todos.get(todo_id)

    def get_agent_todos(self, agent_name: str) -> List[TodoItem]:
        todo_ids = self._agent_todos.get(agent_name, [])
        return [self._todos[tid] for tid in todo_ids if tid in self._todos]

    def get_pending_todos(self, agent_name: Optional[str] = None) -> List[TodoItem]:
        todos = self._agent_todos.get(agent_name, list(self._todos.keys())) if agent_name else list(self._todos.keys())
        return [
            self._todos[tid] for tid in todos
            if tid in self._todos and self._todos[tid].status in (TodoStatus.PENDING, TodoStatus.BLOCKED)
        ]

    def get_incomplete_todos(self, agent_name: Optional[str] = None) -> List[TodoItem]:
        todos = self._agent_todos.get(agent_name, list(self._todos.keys())) if agent_name else list(self._todos.keys())
        return [
            self._todos[tid] for tid in todos
            if tid in self._todos and self._todos[tid].status not in (TodoStatus.COMPLETED, TodoStatus.SKIPPED, TodoStatus.FAILED)
        ]

    def get_all_todos(self) -> List[TodoItem]:
        return list(self._todos.values())

    def get_stats(self) -> dict:
        todos = list(self._todos.values())
        return {
            "total": len(todos),
            "pending": sum(1 for t in todos if t.status == TodoStatus.PENDING),
            "in_progress": sum(1 for t in todos if t.status == TodoStatus.IN_PROGRESS),
            "completed": sum(1 for t in todos if t.status == TodoStatus.COMPLETED),
            "failed": sum(1 for t in todos if t.status == TodoStatus.FAILED),
            "blocked": sum(1 for t in todos if t.status == TodoStatus.BLOCKED),
            "skipped": sum(1 for t in todos if t.status == TodoStatus.SKIPPED),
            "agents": len(self._agent_todos),
        }

    def clear(self):
        self._todos.clear()
        self._agent_todos.clear()


_todo_manager: Optional[TodoManager] = None


def get_todo_manager() -> TodoManager:
    global _todo_manager
    if _todo_manager is None:
        _todo_manager = TodoManager()
    return _todo_manager
