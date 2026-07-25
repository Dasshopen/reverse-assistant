package com.dasshopen.reverseassistant.exporter;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

// On-demand per-instruction disassembly -- the "Listing" half of a
// Ghidra-CodeBrowser-style view. Mirrors DecompileFunctionService's shape
// (same on-demand invocation pattern from the Rust side), but this never
// touches the decompiler and never queries BSim; it only reads Ghidra's
// existing Listing. Supports either one function (the Code Browser's
// per-function view) or an explicit ordered list of functions (a bounded
// page of a "whole program" listing) -- never the whole program in one
// call, since that produced 250k+ instructions on a real large DLL in
// testing and would make for an unusably large single response.
public final class FunctionDisassemblyService {

    private final DisassemblyResultJsonWriter jsonWriter;
    private final AtomicUtf8FileWriter fileWriter;

    public FunctionDisassemblyService() {
        jsonWriter = new DisassemblyResultJsonWriter();
        fileWriter = new AtomicUtf8FileWriter();
    }

    public void disassembleAndWrite(
        Program program,
        Address entryAddress,
        Path destination,
        TaskMonitor monitor
    ) throws IOException, CancelledException, MemoryAccessException {
        disassembleManyAndWrite(program, List.of(entryAddress), destination, monitor);
    }

    public void disassembleManyAndWrite(
        Program program,
        List<Address> entryAddresses,
        Path destination,
        TaskMonitor monitor
    ) throws IOException, CancelledException, MemoryAccessException {
        Objects.requireNonNull(program, "program must not be null");
        Objects.requireNonNull(entryAddresses, "entryAddresses must not be null");
        Objects.requireNonNull(destination, "destination must not be null");
        Objects.requireNonNull(monitor, "monitor must not be null");

        List<DisassembledInstructionMetadata> instructions = new ArrayList<>();

        for (Address entryAddress : entryAddresses) {
            monitor.checkCancelled();

            Function function =
                program.getFunctionManager().getFunctionAt(entryAddress);

            if (function == null) {
                throw new IllegalArgumentException(
                    "no function exists at address " + entryAddress
                );
            }

            instructions.addAll(collectInstructions(program, function, monitor));
        }

        fileWriter.write(
            destination,
            jsonWriter.write(List.copyOf(instructions))
        );
    }

    private static List<DisassembledInstructionMetadata> collectInstructions(
        Program program,
        Function function,
        TaskMonitor monitor
    ) throws CancelledException, MemoryAccessException {
        Listing listing = program.getListing();
        AddressSetView body = function.getBody();
        InstructionIterator iterator = listing.getInstructions(body, true);

        String functionAddress = formatAddress(function.getEntryPoint());
        String functionName = function.getName();

        List<DisassembledInstructionMetadata> instructions = new ArrayList<>();

        while (iterator.hasNext()) {
            monitor.checkCancelled();

            Instruction instruction = iterator.next();
            instructions.add(toMetadata(instruction, functionAddress, functionName));
        }

        return List.copyOf(instructions);
    }

    private static DisassembledInstructionMetadata toMetadata(
        Instruction instruction,
        String functionAddress,
        String functionName
    ) throws MemoryAccessException {
        return new DisassembledInstructionMetadata(
            formatAddress(instruction.getAddress()),
            instruction.getLength(),
            formatBytes(instruction.getBytes()),
            instruction.getMnemonicString(),
            formatOperands(instruction),
            categorizeFlow(instruction.getFlowType()),
            instruction.getFallThrough() == null
                ? null
                : formatAddress(instruction.getFallThrough()),
            functionAddress,
            functionName
        );
    }

    private static String formatOperands(Instruction instruction) {
        StringBuilder operands = new StringBuilder();
        int numOperands = instruction.getNumOperands();

        for (int index = 0; index < numOperands; index++) {
            if (index > 0) {
                operands.append(", ");
            }
            operands.append(instruction.getDefaultOperandRepresentation(index));
        }

        return operands.toString();
    }

    // Bucketed via FlowType's own predicates rather than matching its
    // concrete constants (COMPUTED_CALL, CALL_TERMINATOR, INDIRECTION, ...) --
    // there are many of them and new ones can appear across Ghidra versions;
    // the predicates describe what actually matters for a Listing view
    // (does control flow continue, branch, or call elsewhere).
    private static String categorizeFlow(FlowType flowType) {
        if (flowType.isTerminal()) {
            return "terminator";
        }
        if (flowType.isCall()) {
            return flowType.isConditional() ? "conditional_call" : "unconditional_call";
        }
        if (flowType.isJump()) {
            return flowType.isConditional() ? "conditional_jump" : "unconditional_jump";
        }
        if (flowType.isFallthrough()) {
            return "fall_through";
        }
        return "other";
    }

    private static String formatBytes(byte[] bytes) {
        StringBuilder hex = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            hex.append(String.format("%02x", value));
        }
        return hex.toString();
    }

    private static String formatAddress(Address address) {
        return "0x" + Long.toUnsignedString(address.getOffset(), 16);
    }
}
