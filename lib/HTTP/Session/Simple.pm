package HTTP::Session::Simple;
use 5.008005;
use strict;
use warnings;

our $VERSION = "0.01";

use Carp ();
use Digest::HMAC;
use Digest::SHA1 ();
use Cookie::Baker;

use Moo;

has env => (
    is => 'ro',
    required => 1,
);

has store => (
    is => 'ro',
    default => sub { $_[0]->get_store->() },
);

has get_store => (
    is => 'ro',
    required => 1,
);

has session_cookie => (
    is => 'ro',
    required => 1,
    default => sub {
        +{
            httponly => 1,
            secure   => 0,
            name     => 'hss_session',
        },
    },
);

has xsrf_cookie => (
    is => 'ro',
    required => 1,
    default => sub {
        +{
            httponly => 0, # Must be false.
            secure   => 0,
            name     => 'X-XSRF-TOKEN',
        },
    },
);

has hmac_function => (
    is => 'ro',
    default => sub { \&Digest::SHA1::sha1_hex },
);

has keep_empty => (
    is => 'ro',
    default => sub { 1 },
);

has is_dirty => (
    is => 'rw',
    default => sub { 0 },
);

has xsrf_token => (
    is => 'lazy',
);

has data => (
    is => 'lazy',
);


no Moo;

sub BUILD {
    my $self = shift;
    $self->_load_session();
}

sub data {
    my $self = shift;
    unless ($self->{data}) {
        $self->_load_session();
    }
    $self->{data};
}

sub id {
    my $self = shift;
    unless ($self->{id}) {
        $self->_load_session();
    }
    $self->{id};
}

sub _load_session {
    my $self = shift;

    # Load from cookie.
    my $cookies = crush_cookie($self->env->{HTTP_COOKIE});
    if (my $cookie = exists $cookies->{$self->session_cookie->{name}}) {
        my $session_id = $cookie->{val};
        my $data = $self->store->get($session_id);
        if (defined $data) {
            $self->{id}   = $session_id;
            $self->{data} = $data;
            return;
        }
    }

    $self->_new_session();
}

sub _new_session {
    my $self = shift;

    $self->{id}   = $self->_generate_session_id();
    $self->{data} = +{};
    $self->is_dirty(1) if $self->keep_empty;
}

sub _generate_session_id {
    substr(Digest::SHA::sha1_hex(rand() . $$ . {} . time),int(rand(4)),31);
}

sub set {
    my ($self, $key, $value) = @_;
    $self->{data}->{$key} = $value;
    $self->{is_dirty}++;
}

sub get {
    my ($self, $key) = @_;
    $self->{data}->{$key};
}

sub remove {
    my ($self, $key) = @_;
    delete $self->{data}->{$key};
    $self->{is_dirty}++;
}

sub regenerate_id {
    my ($self) = @_;

    # Remove original session from storage.
    my $cookies = crush_cookie($self->env->{HTTP_COOKIE});
    if (my $cookie = exists $cookies->{$self->session_cookie->{name}}) {
        $self->store->remove($cookie->{value});
    }

    # Create new session.
    $self->_new_session();
    $self->is_dirty(1);
}

sub _build_xsrf_token {
    my $self = shift;
    Digest::HMAC::hmac_hex($self->id, $self->salt, $self->hmac_function);
}

sub finalize_plack_response {
    my ($self, $res) = @_;

    return unless $self->is_dirty;

    # Finalize session cookie
    {
        my %cookie = %{$self->session_cookie};
        my $name = delete $cookie{name};
        $res->cookies->{$name} = +{
            %cookie,
            value => $self->id,
        };
    }

    # Finalize xsrf cookie
    {
        my %cookie = %{$self->xsrf_cookie};
        my $name = delete $cookie{name};
        $res->cookies->{$name} = +{
            %cookie,
            value => $self->xsrf_token,
        };
    }
}

1;
__END__

=encoding utf-8

=head1 NAME

HTTP::Session::Simple - It's new $module

=head1 SYNOPSIS

    use HTTP::Session::Simple;

    my $session = HTTP::Session::Simple->new(
        env         => $psgi_env,
        cookie => {
            name => 'sess_id',
        },
        salt        => 's3cr2t',
    );

    # Get session ID
    $session->id;
    # Get session value
    $session->get($key);
    # Store value from session.
    $session->set($key, $value);
    # Remove the key from session data.
    $session->remove($key);
    # Regenerate session ID for defending from session fixation attack.
    $session->regenerate_id();

    # Finalize cookie data.
    $session->finalize_plack_response($res);

=head1 DESCRIPTION

HTTP::Session::Simple is ...

=head1 LICENSE

Copyright (C) tokuhirom.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 AUTHOR

tokuhirom E<lt>tokuhirom@gmail.comE<gt>

=cut

