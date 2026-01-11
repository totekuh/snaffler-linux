use DBI;

my $dbh = DBI->connect(
    "DBI:mysql:database=testdb;host=localhost",
    "dbuser",
    "SuperSecretPassword"
);
