package com.dasshopen.reverseassistant.exporter;

import java.util.List;
import java.util.Objects;
import java.util.Set;

public record DetectedTypeMetadata(
    String name,
    String kind,
    String category,
    Integer size,
    boolean isOpaque,
    boolean isAnonymous,
    List<TypeFieldMetadata> fields,
    List<EnumValueMetadata> enumValues,
    String targetTypeName,
    List<TypeUsageMetadata> usages
) {

    public static final String KIND_STRUCT = "struct";
    public static final String KIND_UNION = "union";
    public static final String KIND_ENUM = "enum";
    public static final String KIND_TYPEDEF = "typedef";

    private static final Set<String> VALID_KINDS = Set.of(
        KIND_STRUCT,
        KIND_UNION,
        KIND_ENUM,
        KIND_TYPEDEF
    );

    public DetectedTypeMetadata {
        Objects.requireNonNull(name, "name must not be null");
        Objects.requireNonNull(kind, "kind must not be null");
        Objects.requireNonNull(category, "category must not be null");
        Objects.requireNonNull(fields, "fields must not be null");
        Objects.requireNonNull(enumValues, "enumValues must not be null");
        Objects.requireNonNull(usages, "usages must not be null");

        if (!VALID_KINDS.contains(kind)) {
            throw new IllegalArgumentException(
                "kind must be one of " + VALID_KINDS + " but was: " + kind
            );
        }

        fields = List.copyOf(fields);
        enumValues = List.copyOf(enumValues);
        usages = List.copyOf(usages);
    }
}
