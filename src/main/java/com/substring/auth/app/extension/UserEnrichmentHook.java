package com.substring.auth.app.extension;

import com.substring.auth.app.auth.entities.User;

import java.util.Map;

public interface UserEnrichmentHook {
    Map<String, Object> enrich(User user);
}
