import logging
import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter
from sqlalchemy import text
from app.api.program import router
from app.config import settings
from app.db import engine

logging.basicConfig(format="%(message)s",level=logging.INFO)
structlog.configure(processors=[structlog.processors.TimeStamper(fmt="iso"),structlog.processors.add_log_level,structlog.processors.JSONRenderer()],logger_factory=structlog.stdlib.LoggerFactory())
provider=TracerProvider(resource=Resource.create({"service.name":"fieldnote-api","deployment.environment":settings.environment}))
try: provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=settings.otel_exporter_otlp_endpoint,insecure=True)))
except Exception: pass
trace.set_tracer_provider(provider)
log_provider=LoggerProvider(resource=Resource.create({"service.name":"fieldnote-api","deployment.environment":settings.environment}))
try:
    log_provider.add_log_record_processor(BatchLogRecordProcessor(OTLPLogExporter(endpoint=settings.otel_exporter_otlp_endpoint,insecure=True)))
    logging.getLogger().addHandler(LoggingHandler(level=logging.INFO,logger_provider=log_provider))
except Exception: pass

app=FastAPI(title="HydraShagy Security Assurance API",version="0.2.0",docs_url="/api/docs" if settings.environment!="production" else None,redoc_url=None)
app.add_middleware(CORSMiddleware,allow_origins=["http://localhost:8080","http://localhost:5173"],allow_credentials=True,allow_methods=["GET","POST","PATCH","PUT","DELETE"],allow_headers=["Authorization","Content-Type","X-Request-ID"])
FastAPIInstrumentor.instrument_app(app)
app.include_router(router)

@app.get("/health/live",tags=["health"])
def live(): return {"status":"ok"}

@app.get("/health/ready",tags=["health"])
def ready():
    with engine.connect() as connection: connection.execute(text("SELECT 1"))
    return {"status":"ready","database":"ok"}
