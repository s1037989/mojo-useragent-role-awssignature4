package Mojo::AWS::Signature4;
use Mojo::Base -base;

use Mojo::Util 'url_escape';

use Digest::SHA;
use Time::Piece;

has access_key       => sub { $ENV{AWS_ACCESS_KEY} or die 'missing "access_key"' };
has action           => sub { die 'missing "action"' };
has authorization    => 1;
has aws_algorithm    => 'AWS4-HMAC-SHA256';
has expires          => undef;
has region           => undef;
has secret_key       => sub { $ENV{AWS_SECRET_KEY} or die 'missing "secret_key"' };
has service          => undef;
#has security_token   => sub { $ENV{AWS_SECURITY_TOKEN} || undef };
has time             => sub { gmtime };
has tx               => sub { die };
has unsigned_payload => 0;
has version          => '2016-11-15';

sub canonical_headers {
  my $self = shift;
  join '', map { lc($_) . ":" . $self->tx->req->headers->to_hash->{$_} . "\n" } @{$self->_header_list};
}

sub canonical_request {
  my $self = shift;
  join "\n", $self->tx->req->method,
             $self->tx->req->url->path->to_abs_string,
             $self->tx->req->url->query->to_string,
             $self->canonical_headers,
             $self->signed_header_list,
             $self->hashed_payload;
}

sub credential {
  my $self = shift;
  join '/', $self->access_key, $self->credential_scope;
}

sub credential_scope {
  my $self = shift;
  join '/', $self->date, $self->region, $self->service, 'aws4_request';
}

sub date { shift->time->ymd('') }

sub date_timestamp { $_[0]->time->ymd('').'T'.$_[0]->time->hms('').'Z' }

sub hashed_payload {
  my $self = shift;
  $self->unsigned_payload ? 'UNSIGNED-PAYLOAD' : Digest::SHA::sha256_hex($self->tx->req->body);
}

sub sign_tx {
  my $self = shift;
  $self->_parse_host;
  $self->tx->req->headers->host($self->tx->req->url->host);
  $self->tx->req->url->query(['Action' => $self->action])
    unless $self->tx->req->url->query->param('Action');
  $self->tx->req->url->query(['Version' => $self->version])
    unless $self->tx->req->url->query->param('Version');
  if ( $self->expires && !$self->authorization ) {
    $self->tx->req->url->query($self->_authz_query);
  } else {
    $self->tx->req->headers->header('X-Amz-Date' => $self->date_timestamp);
    $self->tx->req->headers->header('X-Amz-Expires' => $self->expires) if $self->expires;
    $self->tx->req->headers->authorization($self->_authz_header);
  }
  return $self->tx;
};

sub signature {
  my $self = shift;
  Digest::SHA::hmac_sha256_hex($self->string_to_sign, $self->signing_key);
}

sub signed_header_list { join ';', map { lc($_) } @{shift->_header_list} }

sub signing_key {
  my $self = shift;
  my $kSecret = "AWS4" . $self->secret_key;
  my $kDate = Digest::SHA::hmac_sha256($self->date, $kSecret);
  my $kRegion = Digest::SHA::hmac_sha256($self->region, $kDate);
  my $kService = Digest::SHA::hmac_sha256($self->service, $kRegion);
  return Digest::SHA::hmac_sha256("aws4_request", $kService);
}

sub string_to_sign {
  my $self = shift;
  join "\n", $self->aws_algorithm,
             $self->date_timestamp,
             $self->credential_scope,
             Digest::SHA::sha256_hex($self->canonical_request);
}

sub _authz_header{
  my $self = shift;
  sprintf '%s Credential=%s, SignedHeaders=%s, Signature=%s',
          $self->aws_algorithm,
          $self->credential,
          $self->signed_header_list,
          $self->signature
}

sub _authz_query {
  my $self = shift;
  [
    'X-Amz-Algorithm' => $self->aws_algorithm,
    'X-Amz-Credential' => url_escape($self->credential),
    'X-Amz-Date' => $self->date_timestamp,
    'X-Amz-Expires' => $self->expires,
    'X-Amz-SignedHeaders' => url_escape($self->signed_header_list),
    'X-Amz-Signature' => $self->signature,
  ]
}

sub _header_list { [sort keys %{shift->tx->req->headers->to_hash}] }

sub _parse_host {
  my $self = shift;
  $self->tx->req->url->host =~ /(([^\.]+)\.)?([^\.]+)\.amazonaws.com$/;
  $self->service($3) if $3 && !$self->service;
  die 'missing "service"' unless $self->service;
  $self->region($2) if $2 && !$self->region;
  die 'missing "region"' unless $self->region;
  return $self;
}

1;

=encoding utf8

=head1 NAME

Mojo::UserAgent::Role::AWSSignature4 - Sign a request transaction with an AWS
Signature version 4 authorization header

=head1 SYNOPSIS

  use Mojo::AWS::Signature4;

  my $awssig4 = Mojo::AWS::Signature4->new(tx => $tx);
  say $awssig4->signature;
  my $tx = $awssig4->sign_tx;

=head1 DESCRIPTION

Sign a request transaction with an AWS Signature version 4 authorization header.

=head1 ATTRIBUTES

=head2 access_key

  $access_key = $awssig4->access_key;
  $awssig4    = $awssig4->access_key($string);

The API access key obtained from the AWS IAM user with programmatic access.
Defaults to using the environment variable AWS_ACCESS_KEY.

=head2 action

  $action  = $awssig4->action;
  $awssig4 = $awssig4->action($string);

The action requested of the specified AWS L</"service">.

=head2 authorization

  $auth    = $awssig4->authorization;
  $awssig4 = $awssig4->authorization($bool);

Use the L<Mojo::headers/"authorization"> header to sign the request. If false,
sign the request by appending the authorization to the request URL query.
Defaults to true.

=head2 aws_algorithm

  $aws_algorithm  = $awssig4->aws_algorithm;
  $awssig4        = $awssig4->aws_algorithm($string);

The AWS SSHA1 algorthim to use. Defaults to AWS4-HMAC-SHA256.

=head2 expires

  $expires = $awssig4->expires;
  $awssig4 = $awssig4->expires($seconds);

The expiration of this authorization signature. Defaults to undef.

=head2 region

  $region  = $awssig4->region;
  $awssig4 = $awssig4->region($string);

The AWS region to send the request to. If not set, the value of the second
position after amazonaws.com in the transaction request host is used during
L<signing|/"sign_tx">.

=head2 secret_key

  $secret_key = $awssig4->secret_key;
  $awssig4    = $awssig4->secret_key($string);

The API secret key obtained from the AWS IAM user with programmatic access.
Defaults to using the environment variable AWS_SECRET_KEY.

=head2 service

  $service = $awssig4->service;
  $awssig4 = $awssig4->service($string);

The AWS service to send the request to. If not set, the value of the first
position after amazonaws.com in the transaction request host is used during
L<signing|/"sign_tx">.

=head2 security_token

NOT YET IMPLEMENTED

  $security_token = $awssig4->security_token;
  $awssig4       = $awssig4->security_token($string);

The API security token obtained from Amazon Security Token Service (STS).
Defaults to using the environment variable AWS_SECURITY_TOKEN.

=head2 time

  $time    = $awssig4->time;
  $awssig4 = $awssig4->time(Time::Piece->new);

A L<Time::Piece> object for which to calculate the AWS signature. Defaults to
L<Time::Piece/"gmtime">

=head2 tx

  $tx      = $awssig4->tx;
  $awssig4 = $awssig4->tx(Mojo::Transaction::HTTP->new);

A L<Mojo::Transaction::HTTP> object for which to calculate the AWS signature.
This attribute is required.

=head2 unsigned_payload

  $unsigned_payload = $awssig4->unsigned_payload;
  $awssig4          = $awssig4->unsigned_payload($bool);

Don't sign the payload. Defaults to false.

=head2 version

  $version = $awssig4->version;
  $awssig4 = $awssig4->version($string);

The AWS API version to use. Defaults to 2016-11-15.

=head1 METHODS

=head2 canonical_headers

=head2 canonical_request

=head2 credential

=head2 credential_scope

=head2 date

=head2 date_timestamp

=head2 hashed_payload

=head2 sign_tx

  $tx = $awssig4->sign_tx;

Add the AWS Signature 4 authorization to the L<transaction|/"tx">.

=head2 signature

=head2 signed_header_list

=head2 signing_key

=head2 string_to_sign
 
=head1 CONTRIBUTORS
 
This module is based on the original work of L<Signer::AWSv4> by JLMARTIN
(Github: @pplu).

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2019, Stefan Adams and others.

This program is free software, you can redistribute it and/or modify it under
the terms of the Artistic License version 2.0.
 
=head1 SEE ALSO

L<https://github.com/s1037989/mojo-aws-signature4>, L<Mojo::UserAgent>.

=cut