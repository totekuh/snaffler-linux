using System;
using System.Data.SqlClient;

namespace MyApp
{
    public class DatabaseManager
    {
        private string connectionString = "Data Source=sqlserver.example.com;Initial Catalog=MyDatabase;Password=SuperSecret123;User ID=dbuser;";

        public void Connect()
        {
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                connection.Open();
                // Do database work
            }
        }
    }
}
