use Mojo::Base -strict;

use Test::More;

use Mojo::UserAgent;

my $ua = Mojo::UserAgent->with_roles('+AWSSignature4')->new;
my $ec2 = 'https://us-east-1.ec2.amazonaws.com';
my $awssig4 = {action => 'DescribeVolumes'};

my $tx = $ua->build_tx(GET => $ec2 => awssig4 => $awssig4);
like $tx->req->headers->authorization, qr($ENV{AWS_ACCESS_KEY}), 'authorization contains aws access_key';

SKIP: {
  skip 'set AWS_ACCESS_KEY and AWS_SECRET_KEY to enable this test', 1
    unless $ENV{AWS_ACCESS_KEY} && $ENV{AWS_SECRET_KEYa};
  my $res = $ua->start($tx)->res;
  ok $res->dom->find('requestId'), 'has a requestId';
};

my $tx1 = $ua->build_tx(GET => $ec2 => awssig4 => {%$awssig4, json => {a => 'b'}});
like $tx1->req->headers->authorization, qr($ENV{AWS_ACCESS_KEY}), 'authorization contains aws access_key';
is   $tx1->req->headers->content_type, 'application/json', 'aws request has json content';
is   $tx1->req->json->{a}, 'b', 'right aws json request content';

done_testing;
