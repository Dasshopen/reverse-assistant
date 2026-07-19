package com.dasshopen.reverseassistant.exporter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Objects;

public final class AtomicUtf8FileWriter {

    public void write(Path target, String content)
        throws IOException {

        Objects.requireNonNull(target, "target must not be null");
        Objects.requireNonNull(content, "content must not be null");

        Path absoluteTarget = target
            .toAbsolutePath()
            .normalize();

        Path parentDirectory = absoluteTarget.getParent();

        if (parentDirectory == null ||
            !Files.isDirectory(parentDirectory)) {
            throw new IOException(
                "The destination directory does not exist"
            );
        }

        Path temporaryFile = Files.createTempFile(
            parentDirectory,
            "." + absoluteTarget.getFileName() + ".",
            ".tmp"
        );

        try {
            Files.writeString(
                temporaryFile,
                content,
                StandardCharsets.UTF_8,
                StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING
            );

            moveIntoPlace(temporaryFile, absoluteTarget);
        }
        finally {
            Files.deleteIfExists(temporaryFile);
        }
    }

    private static void moveIntoPlace(
        Path temporaryFile,
        Path target
    ) throws IOException {

        try {
            Files.move(
                temporaryFile,
                target,
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING
            );
        }
        catch (AtomicMoveNotSupportedException exception) {
            Files.move(
                temporaryFile,
                target,
                StandardCopyOption.REPLACE_EXISTING
            );
        }
    }
}