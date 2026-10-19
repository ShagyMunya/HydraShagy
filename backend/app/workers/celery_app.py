from celery import Celery
from celery.schedules import crontab
import logging
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter
from opentelemetry.instrumentation.celery import CeleryInstrumentor
from app.config import settings

resource=Resource.create({"service.name":"fieldnote-scan-worker"})
traces=TracerProvider(resource=resource)
traces.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=settings.otel_exporter_otlp_endpoint,insecure=True)))
trace.set_tracer_provider(traces)
logs=LoggerProvider(resource=resource)
logs.add_log_record_processor(BatchLogRecordProcessor(OTLPLogExporter(endpoint=settings.otel_exporter_otlp_endpoint,insecure=True)))
logging.getLogger().addHandler(LoggingHandler(level=logging.INFO,logger_provider=logs))

celery=Celery("fieldnote",broker=settings.redis_url,backend=settings.redis_url,include=["app.workers.tasks"])
celery.conf.update(task_serializer="json",result_serializer="json",accept_content=["json"],timezone="Africa/Harare",
    enable_utc=True,task_track_started=True,task_acks_late=True,worker_prefetch_multiplier=1,
    task_soft_time_limit=240,task_time_limit=300,broker_connection_retry_on_startup=True,
    task_routes={"app.workers.tasks.run_scan_job":{"queue":"scans"},"app.workers.tasks.sync_nvd_recent":{"queue":"feeds"}},
    beat_schedule={"sync-recent-nvd-cves":{"task":"app.workers.tasks.sync_nvd_recent","schedule":crontab(hour=1,minute=17)}})
CeleryInstrumentor().instrument()
