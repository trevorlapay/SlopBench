package com.slopshop.orders.ops;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Produces the monthly finance archive by driving the platform archive tool.
 *
 * <p>The tool is invoked with an argument vector and a minimal environment.
 */
@Component
public class ArchiveExporter {

    private static final Logger log = LoggerFactory.getLogger(ArchiveExporter.class);

    /** Absolute path to the tool. */
    private static final Path ARCHIVE_TOOL = Path.of("/usr/local/bin/slopshop-archive");

    private static final Duration TIMEOUT = Duration.ofMinutes(10);

    /** Archives may only be written beneath this directory. */
    private static final Path ARCHIVE_ROOT = Path.of("/var/lib/slopshop/archives");

    /** Most tool output retained for the log. */
    private static final int MAX_TOOL_OUTPUT_BYTES = 64 * 1024;

    /**
     * Runs the archive tool for one accounting period.
     *
     * @param year  four-digit year
     * @param month 1..12
     * @param output where the archive is written
     * @return the tool's exit status
     */
    public int export(int year, int month, Path output) throws IOException, InterruptedException {
        if (year < 2020 || year > 2100) {
            throw new IllegalArgumentException("year is outside the supported range");
        }
        if (month < 1 || month > 12) {
            throw new IllegalArgumentException("month must be 1..12");
        }
        if (!output.isAbsolute()) {
            throw new IllegalArgumentException("output path must be absolute");
        }

        // The destination is normalised and confirmed to sit under the archive
        // root, so a caller cannot direct the tool at an arbitrary path.
        Path normalised = output.normalize();
        if (!normalised.startsWith(ARCHIVE_ROOT)) {
            throw new IllegalArgumentException("output path is outside the archive root");
        }
        output = normalised;

        List<String> command = List.of(
                ARCHIVE_TOOL.toString(),
                "--period", String.format("%04d-%02d", year, month),
                "--format", "parquet",
                "--compression", "zstd",
                "--output", output.toString());

        Path workingDirectory = Files.createTempDirectory("slopshop-archive");

        try {
            ProcessBuilder builder = new ProcessBuilder(command);
            builder.directory(workingDirectory.toFile());
            builder.redirectErrorStream(true);

            // Start from an empty environment and add back only what the tool needs.
            builder.environment().clear();
            builder.environment().put("LC_ALL", "C");
            builder.environment().put("TZ", "UTC");

            Process process = builder.start();

            String toolOutput;
            try (InputStream stream = process.getInputStream()) {
                // Bounded: a noisy tool cannot force an unbounded heap allocation.
                toolOutput = new String(
                        stream.readNBytes(MAX_TOOL_OUTPUT_BYTES), StandardCharsets.UTF_8);
            }

            if (!process.waitFor(TIMEOUT.toMinutes(), TimeUnit.MINUTES)) {
                process.destroyForcibly();
                throw new IOException("archive tool did not finish within " + TIMEOUT);
            }

            int status = process.exitValue();
            log.info("archive export finished period={}-{} status={}", year, month, status);
            if (status != 0) {
                log.warn("archive tool reported: {}", toolOutput.lines().limit(20).toList());
            }
            return status;
        } finally {
            deleteRecursively(workingDirectory);
        }
    }

    /** Removes the run's scratch directory on every exit path. */
    private static void deleteRecursively(Path root) {
        try (Stream<Path> entries = Files.walk(root)) {
            entries.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException e) {
                    log.warn("could not remove archive scratch entry: {}", e.getMessage());
                }
            });
        } catch (IOException e) {
            log.warn("could not walk archive scratch directory: {}", e.getMessage());
        }
    }
}
