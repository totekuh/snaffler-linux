import java.sql.DriverManager;
public class Test {
    void run() throws Exception {
        DriverManager.getConnection(
            "jdbc:postgresql://db01:5432/prod",
            "admin",
            "SuperSecret123"
        );
    }
}
