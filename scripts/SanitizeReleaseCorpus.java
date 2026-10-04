// Maintainer-only: sanitize a packaging COPY, never the development database.
import java.nio.file.Path;
import java.sql.*;

class SanitizeReleaseCorpus {
    private static long count(Statement statement, String table) throws SQLException {
        try (ResultSet rows = statement.executeQuery("SELECT COUNT(*) FROM " + table)) {
            rows.next();
            return rows.getLong(1);
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("Expected packaging database base path");
        Path base = Path.of(args[0]).toAbsolutePath().normalize();
        if (!base.getParent().getFileName().toString().equals(".release-assets")) {
            throw new IllegalArgumentException("Only a database inside .release-assets can be sanitized");
        }
        String url = "jdbc:h2:" + base.toString().replace('\\', '/')
            + ";IFEXISTS=TRUE;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;NON_KEYWORDS=key,value";
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            long functions = count(statement, "desctable");
            long executables = count(statement, "exetable");
            if (functions == 0 || executables == 0) throw new IllegalStateException("Empty corpus");
            connection.setAutoCommit(false);
            // IDs and signatures are unchanged. Retain one unique label per row.
            // Repository strings must remain valid local Ghidra URLs. A plain
            // label breaks result deserialization even though SQL is valid.
            statement.executeUpdate("UPDATE repotable SET val = 'ghidra:/C:/ReverseAssistantReferences/reference-' || id");
            statement.executeUpdate("UPDATE pathtable SET val = '/reference/' || id");
            if (functions != count(statement, "desctable") || executables != count(statement, "exetable")) {
                throw new IllegalStateException("Corpus counts changed");
            }
            connection.commit();
            connection.setAutoCommit(true);
            // Rebuild storage to remove obsolete pages containing old paths.
            statement.execute("SHUTDOWN COMPACT");
            System.out.println("Release corpus sanitized: " + functions + " functions; " + executables + " executables.");
        }
    }
}
