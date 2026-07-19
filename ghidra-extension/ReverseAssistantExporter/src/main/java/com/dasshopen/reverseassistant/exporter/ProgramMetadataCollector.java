package com.dasshopen.reverseassistant.exporter;

import java.util.Locale;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.listing.Program;

public final class ProgramMetadataCollector {

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
            formatAddress(findEntryPoint(program))
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

    private static Address findEntryPoint(Program program) {
        AddressIterator entryPoints = program.getSymbolTable()
            .getExternalEntryPointIterator();

        Address lowestEntryPoint = null;

        while (entryPoints.hasNext()) {
            Address candidate = entryPoints.next();

            if (lowestEntryPoint == null ||
                candidate.compareTo(lowestEntryPoint) < 0) {
                lowestEntryPoint = candidate;
            }
        }

        if (lowestEntryPoint == null) {
            throw new IllegalStateException(
                "Ghidra did not identify an executable entry point"
            );
        }

        return lowestEntryPoint;
    }

    private static String formatAddress(Address address) {
        Objects.requireNonNull(address, "address must not be null");

        return "0x" + Long.toUnsignedString(
            address.getOffset(),
            16
        );
    }
}