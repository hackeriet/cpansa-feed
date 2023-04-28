use 5.36.0;
use warnings;

use JSON::Schema::Modern;
use JSON::MaybeXS qw( encode_json decode_json );
use Path::Tiny;
use CPAN::Audit::DB;

my $feed = {};

my $db = CPAN::Audit::DB->db();
foreach my $dist (keys $db->{dists}->%*) {
  foreach my $report ($db->{dists}{$dist}{advisories}->@*) {
    push $feed->{$dist}->@*, {
      cpansa_id         => $report->{id},
      affected_versions => $report->{affected_versions},
      cves              => $report->{cves},
      description       => $report->{description},
      references        => $report->{references},
      reported          => $report->{reported},
      severity          => $report->{severity},
    }
  }
}


my $js = JSON::Schema::Modern->new(validate_formats => 1);
my $schema = decode_json(path("schema.json")->slurp_raw);
my $schema_id = $schema->{'$id'};
$js->add_schema($schema);

my $result = $js->evaluate($schema_id, $feed);
if ($result) {
  print encode_json($feed);
}
else {
  die encode_json($result);
}