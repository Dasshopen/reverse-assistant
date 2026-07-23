package com.dasshopen.reverseassistant.exporter;

import java.util.List;
import java.util.Objects;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

public final class GhidraExportJsonWriter {

    private static final int SCHEMA_VERSION = 2;

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
        List<FunctionMetadata> functions,
        List<GlobalStringMetadata> strings,
        List<DetectedTypeMetadata> types
    ) {
        Objects.requireNonNull(
            metadata,
            "metadata must not be null"
        );
        Objects.requireNonNull(
            functions,
            "functions must not be null"
        );
        Objects.requireNonNull(
            strings,
            "strings must not be null"
        );
        Objects.requireNonNull(
            types,
            "types must not be null"
        );

        JsonObject root = new JsonObject();
        root.addProperty("schema_version", SCHEMA_VERSION);
        root.add("program", createProgramObject(metadata));
        root.add("functions", createFunctionsArray(functions));
        root.add("strings", createGlobalStringsArray(strings));
        root.add("types", createDetectedTypesArray(types));

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

        program.add(
            "external_entry_points",
            createExternalEntryPointsArray(metadata.externalEntryPoints())
        );

        JsonArray requiredLibraries = new JsonArray();

        for (String library : metadata.requiredLibraries()) {
            requiredLibraries.add(library);
        }

        program.add("required_libraries", requiredLibraries);

        return program;
    }

    private static JsonArray createExternalEntryPointsArray(
        List<ExternalEntryPointMetadata> externalEntryPoints
    ) {
        JsonArray array = new JsonArray();

        for (ExternalEntryPointMetadata entryPoint : externalEntryPoints) {
            JsonObject entryPointObject = new JsonObject();

            entryPointObject.addProperty("address", entryPoint.address());

            if (entryPoint.name() == null) {
                entryPointObject.add("name", JsonNull.INSTANCE);
            }
            else {
                entryPointObject.addProperty("name", entryPoint.name());
            }

            entryPointObject.addProperty("kind", entryPoint.kind());

            array.add(entryPointObject);
        }

        return array;
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

        if (metadata.libraryName() == null) {
            function.add("library", JsonNull.INSTANCE);
        }
        else {
            function.addProperty("library", metadata.libraryName());
        }

        if (metadata.thunkTargetAddress() == null) {
            function.add("thunk_target_address", JsonNull.INSTANCE);
        }
        else {
            function.addProperty(
                "thunk_target_address",
                metadata.thunkTargetAddress()
            );
        }

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

    private static JsonArray createGlobalStringsArray(
        List<GlobalStringMetadata> strings
    ) {
        JsonArray array = new JsonArray();

        for (GlobalStringMetadata string : strings) {
            JsonObject stringObject = new JsonObject();

            stringObject.addProperty("address", string.address());
            stringObject.addProperty("value", string.value());
            stringObject.add(
                "references",
                createStringReferencesArray(string.references())
            );

            array.add(stringObject);
        }

        return array;
    }

    private static JsonArray createStringReferencesArray(
        List<StringReferenceMetadata> references
    ) {
        JsonArray array = new JsonArray();

        for (StringReferenceMetadata reference : references) {
            JsonObject referenceObject = new JsonObject();

            referenceObject.addProperty(
                "instruction_address",
                reference.instructionAddress()
            );

            if (reference.functionAddress() == null) {
                referenceObject.add(
                    "function_address",
                    JsonNull.INSTANCE
                );
            }
            else {
                referenceObject.addProperty(
                    "function_address",
                    reference.functionAddress()
                );
            }

            array.add(referenceObject);
        }

        return array;
    }

    private static JsonArray createDetectedTypesArray(
        List<DetectedTypeMetadata> types
    ) {
        JsonArray array = new JsonArray();

        for (DetectedTypeMetadata type : types) {
            JsonObject typeObject = new JsonObject();

            typeObject.addProperty("name", type.name());
            typeObject.addProperty("kind", type.kind());
            typeObject.addProperty("category", type.category());

            if (type.size() == null) {
                typeObject.add("size", JsonNull.INSTANCE);
            }
            else {
                typeObject.addProperty("size", type.size());
            }

            typeObject.addProperty("is_opaque", type.isOpaque());
            typeObject.addProperty("is_anonymous", type.isAnonymous());
            typeObject.add("fields", createTypeFieldsArray(type.fields()));
            typeObject.add("enum_values", createEnumValuesArray(type.enumValues()));

            if (type.targetTypeName() == null) {
                typeObject.add("target_type_name", JsonNull.INSTANCE);
            }
            else {
                typeObject.addProperty("target_type_name", type.targetTypeName());
            }

            typeObject.add("usages", createTypeUsagesArray(type.usages()));

            array.add(typeObject);
        }

        return array;
    }

    private static JsonArray createTypeFieldsArray(
        List<TypeFieldMetadata> fields
    ) {
        JsonArray array = new JsonArray();

        for (TypeFieldMetadata field : fields) {
            JsonObject fieldObject = new JsonObject();

            if (field.name() == null) {
                fieldObject.add("name", JsonNull.INSTANCE);
            }
            else {
                fieldObject.addProperty("name", field.name());
            }

            fieldObject.addProperty("data_type", field.dataType());
            fieldObject.addProperty("offset", field.offset());

            array.add(fieldObject);
        }

        return array;
    }

    private static JsonArray createEnumValuesArray(
        List<EnumValueMetadata> enumValues
    ) {
        JsonArray array = new JsonArray();

        for (EnumValueMetadata enumValue : enumValues) {
            JsonObject enumValueObject = new JsonObject();

            enumValueObject.addProperty("name", enumValue.name());
            enumValueObject.addProperty("value", enumValue.value());

            array.add(enumValueObject);
        }

        return array;
    }

    private static JsonArray createTypeUsagesArray(
        List<TypeUsageMetadata> usages
    ) {
        JsonArray array = new JsonArray();

        for (TypeUsageMetadata usage : usages) {
            JsonObject usageObject = new JsonObject();

            usageObject.addProperty("kind", usage.kind());
            addNullableProperty(usageObject, "function_address", usage.functionAddress());
            addNullableProperty(usageObject, "function_name", usage.functionName());
            addNullableProperty(usageObject, "parameter_name", usage.parameterName());
            addNullableProperty(usageObject, "data_address", usage.dataAddress());
            addNullableProperty(usageObject, "data_label", usage.dataLabel());

            array.add(usageObject);
        }

        return array;
    }

    private static void addNullableProperty(
        JsonObject object,
        String property,
        String value
    ) {
        if (value == null) {
            object.add(property, JsonNull.INSTANCE);
        }
        else {
            object.addProperty(property, value);
        }
    }
}