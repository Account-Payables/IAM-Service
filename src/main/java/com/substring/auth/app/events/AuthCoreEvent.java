package com.substring.auth.app.events;

import org.slf4j.MDC;
import org.springframework.context.ApplicationEvent;

import java.time.Instant;

public abstract class AuthCoreEvent extends ApplicationEvent {

    private final Instant occurredAt;
    private final String traceId;

    protected AuthCoreEvent(Object source) {
        super(source);
        this.occurredAt = Instant.now();
        this.traceId = MDC.get("traceId");
    }

    public Instant getOccurredAt() {
        return occurredAt;
    }

    public String getTraceId() {
        return traceId;
    }
}
