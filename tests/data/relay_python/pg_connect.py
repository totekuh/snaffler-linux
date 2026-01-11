import psycopg2
conn = psycopg2.connect(
    host="db01",
    user="admin",
    password="Winter2024!",
    dbname="prod"
)
