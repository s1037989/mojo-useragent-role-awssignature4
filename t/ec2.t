use Mojo::Base -strict;

use Test::More;

use Mojo::UserAgent;

my $ua = Mojo::UserAgent->with_roles('+AWSSignature4')->new;

my $tx = $ua->build_tx(GET => 'https://us-east-1.ec2.amazonaws.com' => awssig4 => {action => 'DescribeVolumes'});
like $tx->req->headers->authorization, qr($ENV{AWS_ACCESS_KEY}), 'authorization contains access_key';

SKIP: {
  skip 'set AWS_ACCESS_KEY and AWS_SECRET_KEY to enable this test', 1
    unless $ENV{AWS_ACCESS_KEY} && $ENV{AWS_SECRET_KEY};
  my $res = $ua->start($tx)->res;
  ok $res->dom->find('requestId'), 'has a requestId';
};

done_testing;
