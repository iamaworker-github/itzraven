"""
Event Bus - Core event-driven communication system for Itzraven

Provides publish/subscribe messaging for decoupled communication between
components (agents, orchestrator, UI, memory system, etc.)

Phase 2 Implementation: asyncio.Queue-based (in-memory, single-process)
Phase 3+: Redis Streams (distributed, persistent)
"""

import asyncio
import fnmatch
import traceback
from typing import Dict, List, Callable, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
from contextlib import asynccontextmanager

from itzraven.core.events import (
    BaseEvent,
    EventPriority,
    create_event_from_dict,
    AgentStartedEvent,
    AgentCompletedEvent,
    AgentFailedEvent,
)
from itzraven.core.logger import get_logger

logger = get_logger()


@dataclass
class Subscription:
    """Represents a subscription to events"""
    subscription_id: str
    pattern: str  # Event type pattern (supports wildcards)
    handler: Callable
    filter_func: Optional[Callable] = None
    priority: EventPriority = EventPriority.NORMAL
    created_at: datetime = field(default_factory=datetime.now)


class EventBus:
    """
    Event Bus for publish/subscribe messaging

    Features:
    - Async event publishing and delivery
    - Pattern-based subscriptions (wildcards supported)
    - Event filtering
    - Priority handling
    - Error isolation (subscriber errors don't affect others)
    - Backpressure handling

    Example:
        bus = EventBus()

        # Subscribe to events
        @bus.subscribe("agent.started")
        async def on_agent_started(event):
            print(f"Agent started: {event.agent_name}")

        # Publish events
        await bus.publish("agent.started", {
            "agent_name": "Recon Agent",
            "target": "example.com"
        })

        # Start processing events
        await bus.start()
    """

    def __init__(self, max_queue_size: int = 10000):
        """
        Initialize event bus

        Args:
            max_queue_size: Maximum number of events in queue before backpressure
        """
        self.max_queue_size = max_queue_size

        # Event queue (priority queue)
        self._event_queue: asyncio.Queue = asyncio.Queue(maxsize=max_queue_size)

        # Subscriptions: pattern -> list of subscriptions
        self._subscriptions: Dict[str, List[Subscription]] = defaultdict(list)

        # All subscriptions by ID for quick lookup
        self._subscriptions_by_id: Dict[str, Subscription] = {}

        # Event processing task
        self._processor_task: Optional[asyncio.Task] = None
        self._running = False

        # Statistics
        self._stats = {
            "events_published": 0,
            "events_delivered": 0,
            "events_dropped": 0,
            "subscriber_errors": 0,
        }

        # Event history (for debugging, limited size)
        self._event_history: List[BaseEvent] = []
        self._max_history_size = 1000

    async def start(self) -> None:
        """Start the event bus processor"""
        if self._running:
            logger.warning("Event bus already running")
            return

        self._running = True
        self._processor_task = asyncio.create_task(self._process_events())
        logger.info("Event bus started")

    async def stop(self) -> None:
        """Stop the event bus processor"""
        if not self._running:
            return

        self._running = False

        if self._processor_task:
            self._processor_task.cancel()
            try:
                await self._processor_task
            except asyncio.CancelledError:
                pass

        logger.info("Event bus stopped")

    async def publish(
        self,
        event_type: str,
        data: Dict[str, Any],
        priority: EventPriority = EventPriority.NORMAL,
        correlation_id: str = "",
        source: str = "",
    ) -> None:
        """
        Publish an event (convenience method)

        Args:
            event_type: Type of event (e.g., "agent.started")
            data: Event data dictionary
            priority: Event priority
            correlation_id: Correlation ID for tracing
            source: Event source component

        Example:
            await bus.publish("finding.discovered", {
                "title": "SQL Injection",
                "severity": "high"
            })
        """
        # Create event object from type and data
        event = create_event_from_dict(event_type, data)
        event.priority = priority
        if correlation_id:
            event.correlation_id = correlation_id
        if source:
            event.source = source

        await self.publish_event(event)

    async def publish_event(self, event: BaseEvent) -> None:
        """
        Publish an event object

        Args:
            event: Event object to publish

        Raises:
            asyncio.QueueFull: If queue is full (backpressure)
        """
        try:
            # Add to queue (non-blocking with timeout)
            await asyncio.wait_for(
                self._event_queue.put(event),
                timeout=1.0
            )

            self._stats["events_published"] += 1

            # Add to history (limited size)
            self._event_history.append(event)
            if len(self._event_history) > self._max_history_size:
                self._event_history.pop(0)

            logger.debug(f"Published event: {event.event_type} (id={event.event_id})")

        except asyncio.TimeoutError:
            self._stats["events_dropped"] += 1
            logger.error(f"Event queue full, dropping event: {event.event_type}")
            raise asyncio.QueueFull("Event queue is full")

    def subscribe(
        self,
        pattern: str,
        filter_func: Optional[Callable] = None,
        priority: EventPriority = EventPriority.NORMAL,
    ) -> Callable:
        """
        Subscribe to events (decorator)

        Args:
            pattern: Event type pattern (supports wildcards: *, ?)
            filter_func: Optional filter function (event) -> bool
            priority: Subscription priority

        Returns:
            Decorator function

        Example:
            @bus.subscribe("agent.*")
            async def handle_agent_events(event):
                print(f"Agent event: {event.event_type}")

            @bus.subscribe("finding.discovered",
                          filter=lambda e: e.severity == "critical")
            async def handle_critical_findings(event):
                print(f"Critical finding: {event.title}")
        """
        def decorator(handler: Callable) -> Callable:
            subscription_id = self._add_subscription(
                pattern, handler, filter_func, priority
            )
            # Store subscription ID on handler for later unsubscribe
            handler._subscription_id = subscription_id
            return handler

        return decorator

    def _add_subscription(
        self,
        pattern: str,
        handler: Callable,
        filter_func: Optional[Callable],
        priority: EventPriority,
    ) -> str:
        """Add a subscription and return its ID"""
        import uuid

        subscription_id = str(uuid.uuid4())

        subscription = Subscription(
            subscription_id=subscription_id,
            pattern=pattern,
            handler=handler,
            filter_func=filter_func,
            priority=priority,
        )

        self._subscriptions[pattern].append(subscription)
        self._subscriptions_by_id[subscription_id] = subscription

        logger.debug(f"Added subscription: {pattern} (id={subscription_id})")

        return subscription_id

    def unsubscribe(self, handler: Callable) -> None:
        """
        Unsubscribe a handler

        Args:
            handler: Handler function to unsubscribe
        """
        if not hasattr(handler, "_subscription_id"):
            logger.warning("Handler has no subscription ID")
            return

        subscription_id = handler._subscription_id
        subscription = self._subscriptions_by_id.get(subscription_id)

        if not subscription:
            logger.warning(f"Subscription not found: {subscription_id}")
            return

        # Remove from pattern list
        pattern = subscription.pattern
        if pattern in self._subscriptions:
            self._subscriptions[pattern] = [
                s for s in self._subscriptions[pattern]
                if s.subscription_id != subscription_id
            ]

        # Remove from ID lookup
        del self._subscriptions_by_id[subscription_id]

        logger.debug(f"Removed subscription: {pattern} (id={subscription_id})")

    async def _process_events(self) -> None:
        """Process events from queue and deliver to subscribers"""
        logger.info("Event processor started")

        while self._running:
            try:
                # Get event from queue (with timeout to check _running flag)
                try:
                    event = await asyncio.wait_for(
                        self._event_queue.get(),
                        timeout=0.1
                    )
                except asyncio.TimeoutError:
                    continue

                # Deliver event to subscribers
                await self._deliver_event(event)

            except asyncio.CancelledError:
                logger.info("Event processor cancelled")
                break
            except Exception as e:
                logger.error(f"Error in event processor: {e}", exc_info=True)

        logger.info("Event processor stopped")

    async def _deliver_event(self, event: BaseEvent) -> None:
        """
        Deliver event to matching subscribers

        Args:
            event: Event to deliver
        """
        # Find matching subscriptions
        matching_subs = self._find_matching_subscriptions(event)

        if not matching_subs:
            logger.debug(f"No subscribers for event: {event.event_type}")
            return

        # Sort by priority (higher priority first)
        matching_subs.sort(key=lambda s: s.priority.value, reverse=True)

        # Deliver to each subscriber (in parallel)
        tasks = []
        for subscription in matching_subs:
            task = asyncio.create_task(
                self._deliver_to_subscriber(event, subscription)
            )
            tasks.append(task)

        # Wait for all deliveries (with error isolation)
        await asyncio.gather(*tasks, return_exceptions=True)

        self._stats["events_delivered"] += len(matching_subs)

    def _find_matching_subscriptions(self, event: BaseEvent) -> List[Subscription]:
        """
        Find subscriptions that match the event

        Args:
            event: Event to match

        Returns:
            List of matching subscriptions
        """
        matching = []

        for pattern, subscriptions in self._subscriptions.items():
            # Check if event type matches pattern (supports wildcards)
            if fnmatch.fnmatch(event.event_type, pattern):
                for subscription in subscriptions:
                    # Apply filter if present
                    if subscription.filter_func:
                        try:
                            if not subscription.filter_func(event):
                                continue
                        except Exception as e:
                            logger.error(
                                f"Error in filter function: {e}",
                                exc_info=True
                            )
                            continue

                    matching.append(subscription)

        return matching

    async def _deliver_to_subscriber(
        self,
        event: BaseEvent,
        subscription: Subscription
    ) -> None:
        """
        Deliver event to a single subscriber

        Args:
            event: Event to deliver
            subscription: Subscription to deliver to
        """
        try:
            # Call handler (async or sync)
            if asyncio.iscoroutinefunction(subscription.handler):
                await subscription.handler(event)
            else:
                subscription.handler(event)

        except Exception as e:
            self._stats["subscriber_errors"] += 1
            logger.error(
                f"Error in subscriber {subscription.pattern}: {e}",
                exc_info=True
            )

    @asynccontextmanager
    async def agent_context(
        self,
        agent_name: str,
        agent_type: str,
        target: str,
        mode: str = "pentest",
        correlation_id: str = "",
    ):
        """
        Context manager for agent lifecycle events

        Automatically publishes agent.started on enter and
        agent.completed/agent.failed on exit.

        Example:
            async with bus.agent_context("Recon Agent", "recon", "example.com"):
                await do_reconnaissance()
        """
        # Publish agent started event
        start_event = AgentStartedEvent(
            agent_name=agent_name,
            agent_type=agent_type,
            target=target,
            mode=mode,
            correlation_id=correlation_id,
        )
        await self.publish_event(start_event)

        start_time = asyncio.get_event_loop().time()

        try:
            yield
            # Success - publish completed event
            execution_time = asyncio.get_event_loop().time() - start_time
            completed_event = AgentCompletedEvent(
                agent_name=agent_name,
                agent_type=agent_type,
                target=target,
                execution_time=execution_time,
                correlation_id=correlation_id,
            )
            await self.publish_event(completed_event)

        except Exception as e:
            # Failure - publish failed event
            failed_event = AgentFailedEvent(
                agent_name=agent_name,
                agent_type=agent_type,
                target=target,
                error_message=str(e),
                error_type=type(e).__name__,
                stack_trace=traceback.format_exc(),
                correlation_id=correlation_id,
            )
            await self.publish_event(failed_event)
            raise

    def get_stats(self) -> Dict[str, Any]:
        """Get event bus statistics"""
        return {
            **self._stats,
            "queue_size": self._event_queue.qsize(),
            "subscriptions_count": len(self._subscriptions_by_id),
            "running": self._running,
        }

    def get_event_history(self, limit: int = 100) -> List[BaseEvent]:
        """
        Get recent event history

        Args:
            limit: Maximum number of events to return

        Returns:
            List of recent events (newest first)
        """
        return list(reversed(self._event_history[-limit:]))

    def clear_history(self) -> None:
        """Clear event history"""
        self._event_history.clear()


# Global event bus instance
_event_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    """Get global event bus instance"""
    global _event_bus
    if _event_bus is None:
        _event_bus = EventBus()
    return _event_bus


def set_event_bus(event_bus: EventBus) -> None:
    """Set global event bus instance"""
    global _event_bus
    _event_bus = event_bus
