use Mojo::Base -strict;

use Test::More;

use Mojo::AWS::Signature4;
use Mojo::UserAgent;
use Mojo::Util 'md5_sum';

$ENV{AWS_ACCESS_KEY} ||= uc(md5_sum($$.time));
$ENV{AWS_CONNECT_INSTANCEID} ||= md5_sum($ENV{AWS_ACCESS_KEY});
my $no_secret = $ENV{AWS_SECRET_KEY} ? 0 : 1;
$ENV{AWS_SECRET_KEY} ||= uc(md5_sum($ENV{AWS_ACCESS_KEY}));

# Preferred Usage, DWIM
my $ua = Mojo::UserAgent->with_roles('+AWSSignature4')->new;
$ua->awssig4->action('ListUsers');
my $connect = "https://connect.us-east-1.amazonaws.com/users-summary/$ENV{AWS_CONNECT_INSTANCEID}";
diag $connect;
my $tx = $ua->build_tx(GET => $connect);
like   $ua->awssig4->canonical_headers, qr(host:), 'canonical_headers contains host header';
like   $ua->awssig4->canonical_request, qr(host:), 'canonical_request contains host header';
like   $ua->awssig4->credential, qr(^$ENV{AWS_ACCESS_KEY}/\d{8}/us-east-1/connect/aws4_request$), 'right credential';
like   $ua->awssig4->credential_scope, qr(^\d{8}/us-east-1/connect/aws4_request$), 'right credential_scope';
like   $ua->awssig4->date, qr(^\d{8}$), 'got a date';
like   $ua->awssig4->date_timestamp, qr(^\d{8}T\d{6}Z$), 'got a date_timestamp';
like   $ua->awssig4->hashed_payload, qr(^[0-9a-f]{64}$), 'looks like a hashed_payload';
isa_ok $ua->awssig4->sign_tx, 'Mojo::Transaction::HTTP';
like   $ua->awssig4->signature, qr(^[0-9a-f]{64}$), 'looks like a signature';
is     $ua->awssig4->signed_header_list, 'accept-encoding;host;user-agent;x-amz-date', 'right signed_header_list';
ok     $ua->awssig4->signing_key, 'got _something_';
like   $ua->awssig4->string_to_sign, qr(^AWS4-HMAC-SHA256), 'looks like a string to sign';
is     $ua->awssig4->service, 'connect', 'right non-default service'; # introspection
is     $ua->awssig4->expires, undef, 'right default expires';
like   $tx->req->headers->authorization, qr($ENV{AWS_ACCESS_KEY}), 'authorization contains aws access_key';
is     $tx->req->headers->header('X-Amz-Expires'), undef, 'right default expires';
# Actually connect to AWS
SKIP: {
  skip 'set AWS_SECRET_KEY to enable this test', 4 if $no_secret;
  $tx = $ua->start($tx);
  is $tx->req->headers->header('X-Amz-Expires'), undef, 'right default expires';
  ok exists $tx->res->json->{NextToken}, 'found NextToken json key';
};

done_testing;
