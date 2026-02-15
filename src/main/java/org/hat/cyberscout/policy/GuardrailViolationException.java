package org.hat.cyberscout.policy;

public class GuardrailViolationException extends RuntimeException {

    public GuardrailViolationException(String message) {
        super(message);
    }
}
