import psycopg2

# PostgreSQL connection
conn = psycopg2.connect(
    host="localhost",
    database="mydb",
    user="dbuser",
    password="dbpass123"
)
