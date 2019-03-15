use Mojo::Base -strict;

use Test::More;

use Mojo::AWS::Signature4;
use Mojo::UserAgent;
use Mojo::Util 'md5_sum';

$ENV{AWS_ACCESS_KEY} ||= uc(md5_sum($$.time));
my $no_secret = $ENV{AWS_SECRET_KEY} ? 0 : 1;
$ENV{AWS_SECRET_KEY} ||= uc(md5_sum($ENV{AWS_ACCESS_KEY}));

# Without using a role
my $ua = Mojo::UserAgent->new;
my $ec2 = 'https://us-east-1.ec2.amazonaws.com?Action=DescribeVolumes';
my $awssig4 = Mojo::AWS::Signature4->new(tx => $ua->build_tx(GET => $ec2));
my $tx = $awssig4->sign_tx;
is   $awssig4->expires, undef, 'right default expires';
like $tx->req->headers->authorization, qr($ENV{AWS_ACCESS_KEY}), 'authorization contains aws access_key';
is   $tx->req->headers->header('X-Amz-Expires'), undef, 'right default expires';

# Preferred Usage, with options
$ua = Mojo::UserAgent->with_roles('+AWSSignature4')->new;
$awssig4 = Mojo::AWS::Signature4->new(expires => 600, region => 'us-east-1', action => 'DescribeVolumes');
$ec2 = 'https://ec2.amazonaws.com';
$tx = $ua->awssig4($awssig4)->build_tx(GET => $ec2);
is   $ua->awssig4->service, 'ec2', 'right non-default service';
is   $ua->awssig4->region, 'us-east-1', 'right non-default region';
is   $ua->awssig4->action, 'DescribeVolumes', 'right non-default action';
is   $ua->awssig4->expires, 600, 'right non-default expires';
like $tx->req->headers->authorization, qr($ENV{AWS_ACCESS_KEY}), 'authorization contains aws access_key';
is   $tx->req->headers->header('X-Amz-Expires'), 600, 'right non-default expires';

# Signed query, as opposed to signed authorization header
$ua = Mojo::UserAgent->with_roles('+AWSSignature4')->new;
$awssig4 = Mojo::AWS::Signature4->new(expires => 600, authorization => 0);
$ec2 = 'https://us-east-1.ec2.amazonaws.com?Action=DescribeVolumes';
$tx = $ua->awssig4($awssig4)->build_tx(GET => $ec2);
is   $ua->awssig4->service, 'ec2', 'right non-default service';
is   $ua->awssig4->expires, 600, 'right non-default expires';
like $tx->req->url->query->param('X-Amz-Credential'), qr($ENV{AWS_ACCESS_KEY}), 'authorization contains aws access_key';
is   $tx->req->url->query->param('X-Amz-Expires'), 600, 'right non-default expires';

# Preferred Usage, DWIM
$ua = Mojo::UserAgent->with_roles('+AWSSignature4')->new;
$ec2 = 'https://us-east-1.ec2.amazonaws.com?Action=DescribeVolumes';
$tx = $ua->build_tx(GET => $ec2);
like   $ua->awssig4->canonical_headers, qr($ENV{AWS_ACCESS_KEY}), 'canonical_headers contains aws access_key';
like   $ua->awssig4->canonical_request, qr($ENV{AWS_ACCESS_KEY}), 'canonical_request contains aws access_key';
like   $ua->awssig4->credential, qr(^$ENV{AWS_ACCESS_KEY}/\d{8}/us-east-1/ec2/aws4_request$), 'right credential';
like   $ua->awssig4->credential_scope, qr(^\d{8}/us-east-1/ec2/aws4_request$), 'right credential_scope';
like   $ua->awssig4->date, qr(^\d{8}$), 'got a date';
like   $ua->awssig4->date_timestamp, qr(^\d{8}T\d{6}Z$), 'got a date_timestamp';
like   $ua->awssig4->hashed_payload, qr(^[0-9a-f]{64}$), 'looks like a hashed_payload';
isa_ok $ua->awssig4->sign_tx, 'Mojo::Transaction::HTTP';
like   $ua->awssig4->signature, qr(^[0-9a-f]{64}$), 'looks like a signature';
is     $ua->awssig4->signed_header_list, 'accept-encoding;authorization;host;user-agent;x-amz-date', 'right signed_header_list';
ok     $ua->awssig4->signing_key, 'got _something_';
like   $ua->awssig4->string_to_sign, qr(^AWS4-HMAC-SHA256), 'looks like a string to sign';
is     $ua->awssig4->service, 'ec2', 'right non-default service'; # introspection
is     $ua->awssig4->expires, undef, 'right default expires';
like   $tx->req->headers->authorization, qr($ENV{AWS_ACCESS_KEY}), 'authorization contains aws access_key';
is     $tx->req->headers->header('X-Amz-Expires'), undef, 'right default expires';
# Actually connect to AWS
SKIP: {
  skip 'set AWS_SECRET_KEY to enable this test', 4 if $no_secret;
  $tx = $ua->start($tx);
  is $tx->req->headers->header('X-Amz-Expires'), undef, 'right default expires';
  ok $tx->res->dom->find('requestId'), 'has a requestId';
  my $rid1 = $tx->res->dom->find('requestId');
  $tx = $ua->get($ec2);
  ok $tx->res->dom->find('requestId'), 'has a requestId';
  my $rid2 = $tx->res->dom->find('requestId');
  ok $rid1 ne $rid2, 'different request ids';
};

# FWIW
$ua = Mojo::UserAgent->with_roles('+AWSSignature4')->new;
$ec2 = 'https://us-east-1.ec2.amazonaws.com?Action=DescribeVolumes';
$tx = $ua->tap(sub{$_->awssig4->expires(60)})->build_tx(GET => $ec2);
is   $ua->awssig4->expires, 60, 'right non-default expires';
like $tx->req->headers->authorization, qr($ENV{AWS_ACCESS_KEY}), 'authorization contains aws access_key';
is   $tx->req->headers->header('X-Amz-Expires'), 60, 'right non-default expires';

done_testing;
