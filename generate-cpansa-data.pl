use 5.36.0;
use warnings;

use JSON::Schema::Modern;
use JSON::MaybeXS;
use Path::Tiny;
use CPAN::Audit::DB;
use List::Util qw( any all );

my $feed = {};

run();
exit;

sub run {
  my $db = CPAN::Audit::DB->db();
  foreach my $dist (keys $db->{dists}->%*) {
    foreach my $report ($db->{dists}{$dist}{advisories}->@*) {

      # make some weird values compliant with our schema
      _report_hotfixes($report) or next;

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


  my $json = JSON::MaybeXS->new(canonical => 1);
  my $js = JSON::Schema::Modern->new(validate_formats => 1);
  my $schema = $json->decode(path("schema.json")->slurp_raw);
  my $schema_id = $schema->{'$id'};
  $js->add_schema($schema);

  my $result = $js->evaluate($schema_id, $feed);

  if ($result) {
    print $json->encode($feed);
  }
  else {
    die $json->encode($result);
  }
}

# return true if all is well, false if report should be skipped.
sub _report_hotfixes ($report) {
  return unless defined $report->{affected_versions};
  return unless defined $report->{distribution};

  # ensure we have an arrayref and not a single element.
  if (!ref $report->{affected_versions}) {
    warn "$report->{id} has scalar affected_versions. Converted to arrayref.";
    $report->{affected_versions} = [$report->{affected_versions}];
  }

  # we can't continue unless we know the affected_versions.
  if (!all {; defined $_ } $report->{affected_versions}->@*) {
    warn "$report->{id} has undefined values in $report->{affected_versions}. Skipping.";
    return;
  }

  # (silently) convert cves and references to arrayref.
  foreach my $k (qw(cves references)) {
    if (!ref $report->{$k}) {
      if (!defined $report->{$k} || $report->{$k} eq '') {
        $report->{$k} = [];
      }
      else {
        $report->{$k} = [$report->{$k}];
      }
    }
  }

  # now that we have affected_versions as an arrayref,
  # we go through it and sanitize its elements.
  my @sanitized_versions;
  foreach my $version ($report->{affected_versions}->@*) {
    my @raw_ands = split /,/ => $version;
    my @sanitized_ands;
    foreach my $and (@raw_ands) {
      # drop leading spaces.
      if ($and =~ /\A\s+/) {
        warn "$report->{id} has leading spaces in version '$and'! fixing";
        $and =~ s/\A\s+//;
      }

      # forces mandatory symbol before number.
      if ($and =~ /\A(>=?|<=?|=)\d/) {
        push @sanitized_ands, $and; # all is well with the world;
      }
      else {
        if ($and =~ /\A\d/) {
          warn "$report->{id} affected_versions should always provide a sign before the number in: '$version'. Assuming '='";
          push @sanitized_ands, "=$and";
          next;
        }
        # convert "==" to "=".
        elsif ($and =~ /\A==\d/) {
          warn "$report->{id} has '==' in '$version', should be '='";
          push @sanitized_ands, substr($and, 1);
          next;
        }
        else {
          die "fatal: affected_versions must only begin with '>', '<', '<=', '>=', or '='. Found '$and' in '$version'";
        }
      }
    }
    die "$report->{id} has no acceptable version in $version." if @sanitized_ands == 0;
    return 1 if @sanitized_ands == 1;

    # if we are here, @sanitized_ands has 2+ elements:
    if (any { $_ =~ /\A=/ } @sanitized_ands) {
      die "$report->{id} has '=' bundled with other clauses in '$version'";
    }
    else {
      my ($gt_count, $lt_count, $lower_end, $higher_end) = (0, 0, undef, undef);
      foreach my $and (@sanitized_ands) {
        if ($and =~ /\A\s*>=?\s*(\d+)/) {
          $lower_end = $1;
          $gt_count++;
        }
        elsif ($and =~ /\A\s*<=?\s*(\d+)/) {
          $higher_end = $1;
          $lt_count++;
        }
      }
      if ($gt_count > 1 || $lt_count > 1) {
        say "$report->{id} has more than 1 range bundled together in '$version'";
      }
      elsif ($gt_count == 1 && $lt_count == 1 && $lower_end > $higher_end) {
        say "$report->{id} has invalid range in '$version'";
      }
    }
    push @sanitized_versions, join(',', @sanitized_ands);
  }
  $report->{affected_versions} = \@sanitized_versions;
  return 1;
}

