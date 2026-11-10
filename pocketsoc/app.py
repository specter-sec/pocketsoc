"""Bounded orchestration for the local SOC pipeline."""

from __future__ import annotations

import asyncio
import logging
import signal
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from .alerts import TelegramAlerter
from .config import Config, require_safe_bind
from .detectors import LogTailer, RuleEngine, monitor
from .honeypot import serve
from .models import Event
from .reports import write_reports
from .storage import Store

LOG = logging.getLogger(__name__)


class Pipeline:
    def __init__(self, store: Store, config: Config, alerter: TelegramAlerter):
        self.store, self.config, self.alerter = store, config, alerter
        self.engine = RuleEngine(config.rules)
        self.alerts: asyncio.Queue = asyncio.Queue(maxsize=256)
        self.dropped_alerts = 0

    async def emit(self, event: Event) -> None:
        detections = self.engine.evaluate(event)
        stored = event.sanitized(self.config.capture_passwords)
        if event.kind == "log_line" and not self.config.store_all_logs:
            # Detect on the original line, but don't duplicate sensitive raw logs.
            stored = replace(
                stored, message="Log line matched configured detection rules", metadata={}
            )
        if event.kind != "log_line" or detections or self.config.store_all_logs:
            self.store.insert(stored)
        for detection in detections:
            self.store.insert(detection.sanitized())
            if self.alerter.enabled:
                try:
                    self.alerts.put_nowait(detection)
                except asyncio.QueueFull:
                    self.dropped_alerts += 1
                    if self.dropped_alerts == 1 or self.dropped_alerts % 100 == 0:
                        LOG.warning(
                            "Alert queue full; local events retained (%d dropped alerts)",
                            self.dropped_alerts,
                        )

    async def alert_worker(self) -> None:
        while True:
            event = await self.alerts.get()
            try:
                await self.alerter.send(event)
            finally:
                self.alerts.task_done()


async def daily_reports(store: Store, config: Config, stop: asyncio.Event) -> None:
    last_day = None
    while not stop.is_set():
        today = datetime.now(timezone.utc).date()
        previous = today - timedelta(days=1)
        if previous != last_day:
            events = store.for_day(previous)
            if events:
                write_reports(
                    events,
                    previous.isoformat(),
                    config.report_dir,
                    include_html=config.reports_html,
                )
                LOG.info("Wrote daily UTC summary for %s", previous)
            store.purge(config.retention_days)
            last_day = previous
        try:
            await asyncio.wait_for(stop.wait(), timeout=60)
        except asyncio.TimeoutError:
            pass


async def run(config: Config, *, allow_network: bool = False) -> None:
    require_safe_bind(config, allow_network)
    alerter = TelegramAlerter(config.telegram)  # Fail before binding if secrets are missing.
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    with Store(config.db_path) as store:
        store.purge(config.retention_days)
        pipeline = Pipeline(store, config, alerter)
        alert_task = asyncio.create_task(pipeline.alert_worker(), name="telegram")
        collectors = [
            asyncio.create_task(
                serve(config.listeners, pipeline.emit, stop, config.limits), name="honeypots"
            ),
            asyncio.create_task(
                monitor(
                    LogTailer(config.log_paths, config.start_at_end),
                    pipeline.emit,
                    stop,
                    config.poll_seconds,
                ),
                name="logs",
            ),
            asyncio.create_task(daily_reports(store, config, stop), name="reports"),
        ]
        waiter = asyncio.create_task(stop.wait())
        failure = None
        try:
            LOG.info(
                "PocketSOC started; %d listener(s), %d rule(s); Telegram %s",
                len(config.listeners),
                len(config.rules),
                "enabled" if alerter.enabled else "off",
            )
            done, _ = await asyncio.wait([*collectors, waiter], return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                if task is not waiter and not task.cancelled():
                    failure = task.exception()
                    if failure:
                        break
        finally:
            stop.set()
            waiter.cancel()
            try:
                await asyncio.wait_for(asyncio.gather(*collectors, return_exceptions=True), 12)
            except asyncio.TimeoutError:
                for task in collectors:
                    task.cancel()
                await asyncio.gather(*collectors, return_exceptions=True)
            try:
                await asyncio.wait_for(pipeline.alerts.join(), timeout=6)
            except asyncio.TimeoutError:
                LOG.warning("Shutdown alert drain timed out; events remain stored locally")
            alert_task.cancel()
            await asyncio.gather(alert_task, waiter, return_exceptions=True)
            today = datetime.now(timezone.utc).date().isoformat()
            write_reports(
                store.for_day(today), today, config.report_dir, include_html=config.reports_html
            )
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.remove_signal_handler(sig)
            LOG.info("PocketSOC stopped; listeners closed and current UTC summary written")
        if failure:
            raise failure
