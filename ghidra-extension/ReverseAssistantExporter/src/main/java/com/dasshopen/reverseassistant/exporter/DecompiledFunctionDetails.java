package com.dasshopen.reverseassistant.exporter;

import java.util.List;
import java.util.Objects;

public record DecompiledFunctionDetails(
    String decompiledCode,
    String returnType,
    List<FunctionParameterMetadata> parameters,
    String callingConvention
) {

    public DecompiledFunctionDetails {
        Objects.requireNonNull(
            returnType,
            "returnType must not be null"
        );
        Objects.requireNonNull(
            parameters,
            "parameters must not be null"
        );
        Objects.requireNonNull(
            callingConvention,
            "callingConvention must not be null"
        );

        parameters = List.copyOf(parameters);
    }
}
