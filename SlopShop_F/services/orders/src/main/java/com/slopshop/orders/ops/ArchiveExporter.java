package com.slopshop.orders.ops;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
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

        List<String> command = List.of(
                ARCHIVE_TOOL.toString(),
                "--period", String.format("%04d-%02d", year, month),
                "--format", "parquet",
                "--compression", "zstd",
                "--output", output.toString());

        ProcessBuilder builder = new ProcessBuilder(command);
        builder.directory(Files.createTempDirectory("slopshop-archive").toFile());
        builder.redirectErrorStream(true);

        // Start from an empty environment and add back only what the tool needs.
        builder.environment().clear();
        builder.environment().put("LC_ALL", "C");
        builder.environment().put("TZ", "UTC");

        Process process = builder.start();

        String output0;
        try (InputStream stream = process.getInputStream()) {
            output0 = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }

        if (!process.waitFor(TIMEOUT.toMinutes(), TimeUnit.MINUTES)) {
            process.destroyForcibly();
            throw new IOException("archive tool did not finish within " + TIMEOUT);
        }

        int status = process.exitValue();
        log.info("archive export finished period={}-{} status={}", year, month, status);
        if (status != 0) {
            log.warn("archive tool reported: {}", output0.lines().limit(20).toList());
        }
        return status;
    }
}
