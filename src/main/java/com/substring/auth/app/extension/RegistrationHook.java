package com.substring.auth.app.extension;

import com.substring.auth.app.auth.entities.User;

public interface RegistrationHook {

    enum RegistrationSource { EMAIL_PASSWORD, OAUTH2_GOOGLE, OAUTH2_GITHUB }

    void onUserCreated(User user, RegistrationSource source);
}
