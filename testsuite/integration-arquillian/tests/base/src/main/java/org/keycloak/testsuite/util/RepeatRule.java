package org.keycloak.testsuite.util;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

public class RepeatRule implements TestRule {

    @Override
    public Statement apply(Statement statement, Description description) {
        Repeat repeat = description.getAnnotation(Repeat.class);
        if (repeat != null && repeat.value() > 1) {
            return new RepeatStatement(statement, repeat.value(), description);
        }
        return statement;
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.METHOD)
    public @interface Repeat {
        int value() default 1;
    }

    @Override
    public Statement apply(Statement statement, Description description) {
        Repeat repeat = description.getAnnotation(Repeat.class);
        if (repeat != null && repeat.value() > 1) {
            return new RepeatStatement(statement, repeat.value(), description);
        }
        return statement;
    }

    private static class RepeatStatement extends Statement {
        private final Statement statement;
        private final int repeat;
        private final Description description;

        private RepeatStatement(Statement statement, int repeat, Description description) {
            this.statement = statement;
            this.repeat = repeat;
            this.description = description;
        }

        @Override
        public void evaluate() throws Throwable {
            for (int i = 1; i <= repeat; i++) {
                System.out.printf("Running iteration %d/%d of test: %s%n",
                        i, repeat, description.getMethodName());
                try {
                    statement.evaluate();
                } catch (Throwable t) {
                    System.err.printf("Test failed on iteration %d/%d%n", i, repeat);
                    throw t;
                }
            }
            System.out.printf("All %d iterations passed for test: %s%n",
                    repeat, description.getMethodName());
        }
    }
}
