package com.dasshopen.reverseassistant.exporter;

import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

// Ghidra's own "external entry point" concept: any address reachable from
// outside the analyzed code itself -- covers both the program's true
// execution entry and, for a library, its exported functions/data. Not
// called "exports" here: on a plain ELF executable this set is broader and
// noisier than a real DLL's export table (see docs/contracts).
public record ExternalEntryPointMetadata(
    String address,
    String name,
    String kind
) {

    public static final String KIND_FUNCTION = "function";
    public static final String KIND_DATA = "data";
    public static final String KIND_UNKNOWN = "unknown";

    private static final Set<String> VALID_KINDS =
        Set.of(KIND_FUNCTION, KIND_DATA, KIND_UNKNOWN);

    private static final Pattern ADDRESS_PATTERN =
        Pattern.compile("0x[0-9a-f]+");

    public ExternalEntryPointMetadata {
        Objects.requireNonNull(address, "address must not be null");
        Objects.requireNonNull(kind, "kind must not be null");

        if (!ADDRESS_PATTERN.matcher(address).matches()) {
            throw new IllegalArgumentException(
                "address must use the format " +
                    "0x followed by lowercase hexadecimal digits"
            );
        }

        if (!VALID_KINDS.contains(kind)) {
            throw new IllegalArgumentException(
                "kind must be one of " + VALID_KINDS
            );
        }
    }
}
