package com.dasshopen.reverseassistant.exporter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public final class ProgramMetadataCollector {

    // Ghidra's own placeholder namespace for an external library it could
    // not resolve to a real name -- never surfaced as a real dependency.
    private static final String UNKNOWN_LIBRARY_NAMESPACE = "<EXTERNAL>";

    public ProgramMetadata collect(Program program) {
        Objects.requireNonNull(program, "program must not be null");

        return new ProgramMetadata(
            program.getName(),
            normalizeSha256(program.getExecutableSHA256()),
            normalizeFormat(program.getExecutableFormat()),
            normalizeArchitecture(program.getLanguage()
                .getLanguageDescription()),
            program.getLanguage().isBigEndian() ? "big" : "little",
            formatAddress(program.getImageBase()),
            findExternalEntryPoints(program),
            findRequiredLibraries(program)
        );
    }

    private static String normalizeSha256(String sha256) {
        if (sha256 == null || sha256.isBlank()) {
            throw new IllegalStateException(
                "Ghidra did not provide the executable SHA-256"
            );
        }

        return sha256.toLowerCase(Locale.ROOT);
    }

    private static String normalizeFormat(String format) {
        if (format == null || format.isBlank()) {
            throw new IllegalStateException(
                "Ghidra did not provide the executable format"
            );
        }

        String lowercaseFormat = format.toLowerCase(Locale.ROOT);

        if (lowercaseFormat.contains("portable executable")) {
            return "PE";
        }

        if (lowercaseFormat.contains("executable and linking") ||
            lowercaseFormat.equals("elf")) {
            return "ELF";
        }

        if (lowercaseFormat.contains("mach-o")) {
            return "MACH_O";
        }

        if (lowercaseFormat.contains("raw binary")) {
            return "RAW";
        }

        return format.trim();
    }

    private static String normalizeArchitecture(
        LanguageDescription language
    ) {
        String processor = language.getProcessor()
            .toString()
            .toLowerCase(Locale.ROOT);

        int bitSize = language.getSize();

        return switch (processor) {
            case "x86" -> bitSize == 64 ? "x86_64" : "x86";
            case "aarch64" -> "aarch64";
            case "arm" -> bitSize == 64 ? "aarch64" : "arm";
            case "mips" -> bitSize == 64 ? "mips64" : "mips";
            case "powerpc" -> bitSize == 64
                ? "powerpc64"
                : "powerpc";
            case "riscv" -> bitSize == 64 ? "riscv64" : "riscv32";
            default -> normalizeUnknownArchitecture(processor, bitSize);
        };
    }

    private static String normalizeUnknownArchitecture(
        String processor,
        int bitSize
    ) {
        String normalizedProcessor = processor
            .replaceAll("[^a-z0-9]+", "_")
            .replaceAll("^_+|_+$", "");

        if (normalizedProcessor.isBlank()) {
            normalizedProcessor = "unknown";
        }

        return normalizedProcessor + "_" + bitSize;
    }

    private static List<ExternalEntryPointMetadata> findExternalEntryPoints(
        Program program
    ) {
        AddressIterator iterator = program.getSymbolTable()
            .getExternalEntryPointIterator();

        List<Address> addresses = new ArrayList<>();

        while (iterator.hasNext()) {
            addresses.add(iterator.next());
        }

        addresses.sort(
            (left, right) -> left.compareTo(right)
        );

        Listing listing = program.getListing();
        SymbolTable symbolTable = program.getSymbolTable();
        List<ExternalEntryPointMetadata> entryPoints = new ArrayList<>();
        Set<String> seenAddresses = new HashSet<>();

        for (Address address : addresses) {
            String formattedAddress = formatAddress(address);

            if (!seenAddresses.add(formattedAddress)) {
                continue;
            }

            Function function = program.getFunctionManager().getFunctionAt(address);

            if (function != null) {
                entryPoints.add(new ExternalEntryPointMetadata(
                    formattedAddress,
                    function.getName(),
                    ExternalEntryPointMetadata.KIND_FUNCTION
                ));
                continue;
            }

            Data data = listing.getDataAt(address);
            Symbol primarySymbol = symbolTable.getPrimarySymbol(address);
            String name = primarySymbol == null ? null : primarySymbol.getName();

            entryPoints.add(new ExternalEntryPointMetadata(
                formattedAddress,
                name,
                data != null
                    ? ExternalEntryPointMetadata.KIND_DATA
                    : ExternalEntryPointMetadata.KIND_UNKNOWN
            ));
        }

        return List.copyOf(entryPoints);
    }

    private static List<String> findRequiredLibraries(Program program) {
        String[] libraryNames = program.getExternalManager().getExternalLibraryNames();

        return Arrays.stream(libraryNames)
            .filter(name -> !UNKNOWN_LIBRARY_NAMESPACE.equals(name))
            .sorted()
            .toList();
    }

    private static String formatAddress(Address address) {
        Objects.requireNonNull(address, "address must not be null");

        return "0x" + Long.toUnsignedString(
            address.getOffset(),
            16
        );
    }
}