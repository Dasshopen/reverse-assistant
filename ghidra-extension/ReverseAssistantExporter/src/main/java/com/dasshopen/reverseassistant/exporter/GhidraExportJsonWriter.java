package com.dasshopen.reverseassistant.exporter;

import java.util.List;
import java.util.Objects;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

public final class GhidraExportJsonWriter {

    private static final int SCHEMA_VERSION = 1;

    private final Gson gson;

    public GhidraExportJsonWriter() {
        gson = new GsonBuilder()
            .setPrettyPrinting()
            .disableHtmlEscaping()
            .serializeNulls()
            .create();
    }

    public String write(
        ProgramMetadata metadata,
        List<FunctionMetadata> functions
    ) {
        Objects.requireNonNull(
            metadata,
            "metadata must not be null"
        );
        Objects.requireNonNull(
            functions,
            "functions must not be null"
        );

        JsonObject root = new JsonObject();
        root.addProperty("schema_version", SCHEMA_VERSION);
        root.add("program", createProgramObject(metadata));
        root.add("functions", createFunctionsArray(functions));

        return gson.toJson(root) + "\n";
    }

    private static JsonObject createProgramObject(
        ProgramMetadata metadata
    ) {
        JsonObject program = new JsonObject();

        program.addProperty("name", metadata.name());
        program.addProperty("sha256", metadata.sha256());
        program.addProperty("format", metadata.format());
        program.addProperty(
            "architecture",
            metadata.architecture()
        );
        program.addProperty(
            "endianness",
            metadata.endianness()
        );
        program.addProperty(
            "image_base",
            metadata.imageBase()
        );

        JsonArray entryPoints = new JsonArray();

        for (String entryPoint : metadata.entryPoints()) {
            entryPoints.add(entryPoint);
        }

        program.add("entry_points", entryPoints);

        return program;
    }

    private static JsonArray createFunctionsArray(
        List<FunctionMetadata> functions
    ) {
        JsonArray array = new JsonArray();

        for (FunctionMetadata function : functions) {
            array.add(createFunctionObject(function));
        }

        return array;
    }

    private static JsonObject createFunctionObject(
        FunctionMetadata metadata
    ) {
        JsonObject function = new JsonObject();

        function.addProperty(
            "entry_address",
            metadata.entryAddress()
        );
        function.addProperty("name", metadata.name());
        function.addProperty(
            "return_type",
            metadata.returnType()
        );
        function.add(
            "parameters",
            createParametersArray(metadata.parameters())
        );
        function.addProperty(
            "is_external",
            metadata.isExternal()
        );
        function.addProperty(
            "is_thunk",
            metadata.isThunk()
        );

        if (metadata.decompiledCode() == null) {
            function.add(
                "decompiled_code",
                JsonNull.INSTANCE
            );
        }
        else {
            function.addProperty(
                "decompiled_code",
                metadata.decompiledCode()
            );
        }

        function.add(
            "calls",
            createCallsArray(metadata.calls())
        );
        function.add(
            "strings",
            createStringsArray(metadata.strings())
        );

        return function;
    }

    private static JsonArray createParametersArray(
        List<FunctionParameterMetadata> parameters
    ) {
        JsonArray array = new JsonArray();

        for (FunctionParameterMetadata parameter : parameters) {
            JsonObject parameterObject = new JsonObject();

            parameterObject.addProperty(
                "name",
                parameter.name()
            );
            parameterObject.addProperty(
                "data_type",
                parameter.dataType()
            );

            array.add(parameterObject);
        }

        return array;
    }

    private static JsonArray createCallsArray(
        List<FunctionCallMetadata> calls
    ) {
        JsonArray array = new JsonArray();

        for (FunctionCallMetadata call : calls) {
            JsonObject callObject = new JsonObject();

            if (call.targetAddress() == null) {
                callObject.add(
                    "target_address",
                    JsonNull.INSTANCE
                );
            }
            else {
                callObject.addProperty(
                    "target_address",
                    call.targetAddress()
                );
            }

            callObject.addProperty(
                "target_name",
                call.targetName()
            );

            array.add(callObject);
        }

        return array;
    }

    private static JsonArray createStringsArray(
        List<String> strings
    ) {
        JsonArray array = new JsonArray();

        for (String value : strings) {
            array.add(value);
        }

        return array;
    }
}