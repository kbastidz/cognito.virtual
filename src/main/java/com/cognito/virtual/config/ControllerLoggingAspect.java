package com.cognito.virtual.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

import java.util.Arrays;

@Slf4j
@Aspect
@Component
public class ControllerLoggingAspect {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Around("execution(public * com.cognito.virtual.controller..*(..)) || execution(public * com.cognito.virtual.service..*(..))")
    public Object logRequestResponse(ProceedingJoinPoint joinPoint) throws Throwable {
        String methodName = joinPoint.getSignature().toShortString();
        Object[] args = joinPoint.getArgs();

        String argsStr = Arrays.stream(args)
                .map(arg -> {
                    try {
                        return objectMapper.writeValueAsString(arg);
                    } catch (Exception e) {
                        return String.valueOf(arg);
                    }
                })
                .reduce((a,b) -> a + ", " + b)
                .orElse("");

        log.info("Class/Functions: {} Request: {}", methodName, argsStr);

        Object result = joinPoint.proceed();

        String resultStr;
        try {
            resultStr = objectMapper.writeValueAsString(result);
        } catch (Exception e) {
            resultStr = String.valueOf(result);
        }

        log.info("Class/Functions: {} with Response: {}", methodName, resultStr);

        return result;
    }
}
