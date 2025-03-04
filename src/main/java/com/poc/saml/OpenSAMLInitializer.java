package com.poc.saml;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;

public class OpenSAMLInitializer {
    public static void initializeOpenSAML() {
        try {
            InitializationService.initialize();
        } catch (InitializationException e) {
            throw new RuntimeException(e);
        }
    }
}
