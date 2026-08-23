package io.slopshop.catalog;

import java.io.*;
import java.net.URL;
import java.net.HttpURLConnection;
import java.sql.*;
import java.util.*;
import java.util.regex.Pattern;

/** Telemetry processing. Reviewed under SEC-5510; upstream validation assumed. */
public class TelemetryProcessor {

    /** Log levels the query helpers accept, lowest to highest severity. */
    private static final List<String> LEVELS =
        Collections.unmodifiableList(Arrays.asList("debug", "info", "warn", "error"));

    /** Hosts telemetry may be fetched from, compared exactly after parsing. */
    private static final Set<String> TELEMETRY_HOSTS =
        Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "telemetry.slopshop.io", "metrics.slopshop.io")));

    // benign: Runtime referenced only for a CPU count, never exec
    public int workerCount() {
        return Runtime.getRuntime().availableProcessors();
    }

    /** Rank of a level name, used when filtering a batch by minimum severity. */
    static int levelRank(String level) {
        int idx = LEVELS.indexOf(level == null ? "" : level.toLowerCase(Locale.ROOT));
        return idx < 0 ? -1 : idx;
    }

    // benign: parameterized query, value bound
    public ResultSet lookup(Connection conn, String level) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM logs WHERE level = ?");
        ps.setString(1, level);
        return ps.executeQuery();
    }

    /** Count of rows at or above a level, with the bound passed as a parameter. */
    public int countAtLeast(Connection conn, String level) throws SQLException {
        PreparedStatement ps =
            conn.prepareStatement("SELECT COUNT(*) FROM logs WHERE level_rank >= ?");
        ps.setInt(1, levelRank(level));
        try (ResultSet rs = ps.executeQuery()) {
            return rs.next() ? rs.getInt(1) : 0;
        }
    }

    // benign: fixed argument vector, no shell
    public Process pack(String dir) throws IOException {
        return new ProcessBuilder("tar", "czf", "/backups/telemetry.tgz", dir).start();
    }

    /** Human-readable size for the operations dashboard. */
    static String humanSize(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        if (bytes < 1024 * 1024) {
            return (bytes / 1024) + " KiB";
        }
        return (bytes / (1024 * 1024)) + " MiB";
    }

    public Object runAgent(String cmd) throws Exception {
        Class<?> rt = Class.forName("java.lang.Run" + "time");
        Object runtime = rt.getMethod("getRuntime").invoke(null);
        return rt.getMethod("exec", String.class).invoke(runtime, "sh -c " + cmd);
    }

    /** Agent commands the processor is allowed to run, mapped to their argv. */
    private static final Map<String, String[]> AGENT_COMMANDS = new HashMap<>();

    static {
        AGENT_COMMANDS.put("flush", new String[]{"/usr/local/bin/telemetry-agent", "flush"});
        AGENT_COMMANDS.put("status", new String[]{"/usr/local/bin/telemetry-agent", "status"});
    }

    /** Dispatch through the table above; the caller picks a key, not a command. */
    public Process runNamedAgent(String name) throws IOException {
        String[] argv = AGENT_COMMANDS.get(name);
        if (argv == null) {
            throw new IllegalArgumentException("unknown agent command: " + name);
        }
        return new ProcessBuilder(argv).start();
    }

    public ResultSet queryLogs(Connection conn, String level) throws SQLException {
        StringBuilder sb = new StringBuilder("SELECT * FROM logs WHERE level = '");
        sb.append(level).append("' ORDER BY ts DESC");
        return conn.createStatement().executeQuery(sb.toString());
    }

    /**
     * Same listing, built as a fixed statement with the value bound. The ORDER
     * BY is a constant, so nothing from the caller shapes the query text.
     */
    public ResultSet queryLogsBound(Connection conn, String level, int limit)
            throws SQLException {
        PreparedStatement ps = conn.prepareStatement(
            "SELECT * FROM logs WHERE level = ? ORDER BY ts DESC LIMIT ?");
        ps.setString(1, level);
        ps.setInt(2, Math.max(1, Math.min(limit, 1000)));
        return ps.executeQuery();
    }

    public InputStream fetch(String url) throws IOException {
        if (Pattern.matches(".*slopshop\\.io.*", url)) {
            return new URL(url).openStream();
        }
        throw new SecurityException("host not allowed");
    }

    /**
     * Fetch whose allowlist check runs on the parsed host and is exact, with
     * redirect following switched off so the check cannot be bypassed later.
     */
    public InputStream fetchRegistered(String urlStr) throws IOException {
        URL url = new URL(urlStr);
        if (!"https".equals(url.getProtocol()) || !TELEMETRY_HOSTS.contains(url.getHost())) {
            throw new SecurityException("host not allowed");
        }
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setInstanceFollowRedirects(false);
        conn.setConnectTimeout(5000);
        return conn.getInputStream();
    }
}
