package com.dasshopen.reverseassistant.exporter;

import java.util.Objects;
import java.util.regex.Pattern;

// One instruction inside a function's on-demand disassembly listing.
// `flowCategory` is a small, stable bucket derived from Ghidra's own
// FlowType predicates (isCall/isJump/isConditional/isTerminal/isFallthrough)
// rather than its many concrete FlowType constants, so this contract stays
// meaningful even if Ghidra adds new flow types in a future version.
public record DisassembledInstructionMetadata(
    String address,
    int length,
    String bytes,
    String mnemonic,
    String operands,
    String flowCategory,
    String fallThroughAddress
) {

    private static final Pattern ADDRESS_PATTERN =
        Pattern.compile("0x[0-9a-f]+");
    private static final Pattern BYTES_PATTERN =
        Pattern.compile("[0-9a-f]*");

    public DisassembledInstructionMetadata {
        Objects.requireNonNull(address, "address must not be null");
        Objects.requireNonNull(bytes, "bytes must not be null");
        Objects.requireNonNull(mnemonic, "mnemonic must not be null");
        Objects.requireNonNull(operands, "operands must not be null");
        Objects.requireNonNull(flowCategory, "flowCategory must not be null");

        if (!ADDRESS_PATTERN.matcher(address).matches()) {
            throw new IllegalArgumentException(
                "address must use the format 0x followed by lowercase hexadecimal digits"
            );
        }

        if (!BYTES_PATTERN.matcher(bytes).matches()) {
            throw new IllegalArgumentException(
                "bytes must be a lowercase hexadecimal string"
            );
        }

        if (fallThroughAddress != null &&
            !ADDRESS_PATTERN.matcher(fallThroughAddress).matches()) {
            throw new IllegalArgumentException(
                "fallThroughAddress must use the format 0x followed by lowercase hexadecimal digits"
            );
        }
    }
}
