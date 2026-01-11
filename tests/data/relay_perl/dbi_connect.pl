use DBI;

my $dbh = DBI->connect(
  "DBI:mysql:database=prod;host=db01",
  "admin",
  "SuperSecret123"
);
