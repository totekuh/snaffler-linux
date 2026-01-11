require 'dbi'

dbh = DBI.connect(
  "DBI:Pg:database=prod;host=db01",
  "admin",
  "SuperSecret123"
)
