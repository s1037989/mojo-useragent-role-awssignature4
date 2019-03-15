package Mojo::UserAgent::Role::AWSSignature4;
use Mojo::Base -role;

use Mojo::AWS::Signature4;

has awssig4 => sub { Mojo::AWS::Signature4->new };

around build_tx => sub {
  my ($orig, $self) = (shift, shift);
  my $tx = $orig->($self, @_);
  $self->awssig4 ? $self->awssig4->tx($tx)->sign_tx : $tx;
};

1;

=encoding utf8

=head1 NAME

Mojo::UserAgent::Role::AWSSignature4 - Automatically sign transactions with AWS
Signature version 4

=head1 SYNOPSIS

  use Mojo::UserAgent;

  my $ua = Mojo::UserAgent->with_roles('+AWSSignature4')->new;
  my $tx = $ua->get('https://us-east-1.ec2.amazonaws.com?Action=DescribeVolumes');
  say $tx->req->headers->authorization;
  say $ua->awssig4->signature;

=head1 DESCRIPTION

L<Mojo::UserAgent::Role::AWSSignature4> modifies the L<Mojo::UserAgent/"build_tx">
method by wrapping around it with a L<role|Role::Tiny> and signing the
transaction using the AWS Signature version 4 by either adding an authorization
header or modifying the request URL query.

=head1 ATTRIBUTES

=head2 awssig4

  $awssig4 = $ua->awssig4;
  $ua      = $ua->awssig4(Mojo::AWS::Signature4->new);

Defaults to a new L<Mojo::AWS::Signature4> instance, but if this attribute is
not defined, the method modifier provider by this L<role|Role::Tiny> will have
no effect.

  # Sign the request transaction
  $ua->get($url);

  # Don't sign the request transaction
  $ua->awssig4(undef)->get($url);

  # Sign the request transaction using the URL query
  $ua->awssig4->authorization(0)->expires(60);
  $ua->get($url);

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2019, Stefan Adams and others.

This program is free software, you can redistribute it and/or modify it under
the terms of the Artistic License version 2.0.
 
=head1 SEE ALSO

L<https://github.com/s1037989/mojo-aws-signature4>, L<Mojo::UserAgent>.

=cut