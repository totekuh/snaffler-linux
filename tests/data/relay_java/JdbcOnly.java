import java.sql.DriverManager;
public class Test {
    void run() throws Exception {
        DriverManager.getConnection("jdbc:mysql://db01:3306/prod");
    }
}
