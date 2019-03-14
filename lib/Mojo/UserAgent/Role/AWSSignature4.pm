package Mojo::UserAgent::Role::AWSSignature4;
use Mojo::Base -role;

use Digest::SHA;
use Time::Piece;

has access_key       => sub { $ENV{AWS_ACCESS_KEY} or die 'missing "access_key"' };
has action           => sub { die 'missing "action"' };
has authorization    => 1;
has aws_algorithm    => 'AWS4-HMAC-SHA256';
has expires          => 86_400;
has region           => undef;
has secret_key       => sub { $ENV{AWS_SECRET_KEY} or die 'missing "secret_key"' };
has service          => undef;
has session_token    => sub { $ENV{AWS_SESSION_TOKEN} || undef };
has time             => sub { gmtime };
has unsigned_payload => 0;
has version          => '2016-11-15';
has _tx              => sub { die };

around build_tx => sub {
  my ($orig, $self) = (shift, shift);
  $self->transactor->add_generator(awssig4 => sub {
    my ($transactor, $tx, $config) = @_;
    foreach ( keys %$config ) {
      if ( my $cb = $transactor->generators->{$_} ) {
        $transactor->$cb($tx, delete $config->{$_});
      }
    }
    my $aws = $self->new({%$config, _tx => $tx})->_parse_host;
    $tx->req->url->query(['Action' => $aws->action])
      unless $tx->req->url->query->param('Action');
    $tx->req->url->query(['Version' => $aws->version])
      unless $tx->req->url->query->param('Version');
    $tx->req->headers->host($tx->req->url->host);
    $tx->req->headers->header('X-Amz-Date' => $aws->_date_timestamp);
    $tx->req->headers->header('X-Amz-Expires' => $aws->expires) if $aws->expires;
    if ( $aws->authorization ) {
      $tx->req->headers->authorization($aws->_authorization);
    } else {
      $tx->req->url->query(['X-Amz-Signature' => $self->_signature]);
    }
  });
  $orig->($self, @_);
};

sub _authorization {
  my $self = shift;
  sprintf '%s Credential=%s/%s, SignedHeaders=%s, Signature=%s',
          $self->aws_algorithm,
          $self->access_key,
          $self->_credential_scope,
          $self->_signed_header_list,
          $self->_signature
}

sub _canonical_headers {
  my $self = shift;
  join '', map { lc($_) . ":" . $self->_tx->req->headers->to_hash->{$_} . "\n" } @{$self->_header_list};
}

sub _canonical_request {
  my $self = shift;
  join "\n", $self->_tx->req->method,
             $self->_tx->req->url->path->to_abs_string,
             $self->_tx->req->url->query->to_string,
             $self->_canonical_headers,
             $self->_signed_header_list,
             $self->_hashed_payload;
}

sub _credential_scope {
  my $self = shift;
  join '/', $self->_date, $self->region, $self->service, 'aws4_request';
}

sub _date { shift->time->ymd('') }

sub _date_timestamp { $_[0]->time->ymd('').'T'.$_[0]->time->hms('').'Z' }

sub _hashed_payload {
  my $self = shift;
  return $self->unsigned_payload ? 'UNSIGNED-PAYLOAD' : Digest::SHA::sha256_hex($self->_tx->req->body);
}

sub _header_list { [sort keys %{shift->_tx->req->headers->to_hash}] }

sub _parse_host {
  my $self = shift;
  $self->_tx->req->url->host =~ /(([^\.]+)\.)?([^\.]+)\.amazonaws.com$/;
  $self->service($3) if $3 && !$self->service;
  die 'missing "service"' unless $self->service;
  $self->region($2) if $2 && !$self->region;
  die 'missing "region"' unless $self->region;
  return $self;
}

sub _signature {
  my $self = shift;
  Digest::SHA::hmac_sha256_hex($self->_string_to_sign, $self->_signing_key);
}

sub _signed_header_list { join ';', map { lc($_) } @{shift->_header_list} }

sub _signing_key {
  my $self = shift;
  my $kSecret = "AWS4" . $self->secret_key;
  my $kDate = Digest::SHA::hmac_sha256($self->_date, $kSecret);
  my $kRegion = Digest::SHA::hmac_sha256($self->region, $kDate);
  my $kService = Digest::SHA::hmac_sha256($self->service, $kRegion);
  return Digest::SHA::hmac_sha256("aws4_request", $kService);
}

sub _string_to_sign {
  my $self = shift;
  join "\n", $self->aws_algorithm,
             $self->_date_timestamp,
             $self->_credential_scope,
             Digest::SHA::sha256_hex($self->_canonical_request);
}

1;

=encoding utf8

=head1 NAME

Mojo::UserAgent::Role::AWSSignature4 - Add a generator for adding AWS Signature
version 4 authorization header to a transaction request

=head1 SYNOPSIS

  use Mojo::UserAgent;

  my $ua = Mojo::UserAgent->with_roles('+AWSSignature4')->new;

  $ua->get('https://ec2.amazonaws.com' => awssig4 => {action => 'DescribeVolumes'});

=head1 DESCRIPTION

Add a generator for adding AWS Signature version 4 authorization header to a
transaction request.

=head1 GENERATORS

=head2 awssig4

  $ua->get($url => awssig4 => {action => 'DescribeVolumes'});
  $ua->get($url => awssig4 => {action => 'DescribeVolumes', json => {a => 'b'}});

Generate AWS authorization signature. See L<Mojo::UserAgent::Transactor/"tx">
for more.

Any hash keys supplied to this generator that are themselves registered
generators will be removed from the hash and processed, in no particular order.

Any remaining hash keys supplied to this generator are passed as attributes to
this module. The requested host is used to detect the L</"service"> and
L</"region"> if not already specified.

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

The expiration of this authorization signature. Defaults to one day.

=head2 region

  $region  = $awssig4->region;
  $awssig4 = $awssig4->region($string);

The AWS region to send the request to. Defaults to the value of the second
position after amazonaws.com in the transaction request host.

=head2 secret_key

  $secret_key = $awssig4->secret_key;
  $awssig4    = $awssig4->secret_key($string);

The API secret key obtained from the AWS IAM user with programmatic access.
Defaults to using the environment variable AWS_SECRET_KEY.

=head2 service

  $service = $awssig4->service;
  $awssig4 = $awssig4->service($string);

The AWS service to send the request to. Defaults to the value of the first
position after amazonaws.com in the transaction request host.

=head2 session_token

  $session_token = $awssig4->session_token;
  $awssig4       = $awssig4->session_token($string);

The API session token obtained from ____.
Defaults to using the environment variable AWS_SESSION_TOKEN.

=head2 time

  $time    = $awssig4->time;
  $awssig4 = $awssig4->time(Time::Piece->new);

A L<Time::Piece> object for which to calculate the AWS signature. Defaults to
L<Time::Piece/"gmtime">

=head2 unsigned_payload

  $unsigned_payload = $awssig4->unsigned_payload;
  $awssig4          = $awssig4->unsigned_payload($bool);

Don't sign the payload. Defaults to false.

=head2 version

  $version = $awssig4->version;
  $awssig4 = $awssig4->version($string);

The AWS API version to use. Defaults to 2016-11-15.

=head1 CONTRIBUTORS
 
This module is based on the original work of L<Signer::AWSv4> by JLMARTIN
(Github: @pplu).

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2019, Stefan Adams and others.

This program is free software, you can redistribute it and/or modify it under
the terms of the Artistic License version 2.0.
 
=head1 SEE ALSO

L<https://github.com/s1037989/mojo-useragent-role-awssignature4>, L<Mojo::UserAgent>.

=cut