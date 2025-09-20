from __future__ import annotations

import os

from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

_provider: TracerProvider | None = None


def init_tracing(service_name: str = "provis-ucg") -> None:
    global _provider
    if _provider:
        return
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
    resource = Resource.create({"service.name": service_name})
    _provider = TracerProvider(resource=resource)
    processor = BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{endpoint}/v1/traces"))
    _provider.add_span_processor(processor)
    from opentelemetry import trace

    trace.set_tracer_provider(_provider)


def get_tracer(name: str):
    from opentelemetry import trace

    return trace.get_tracer(name)
