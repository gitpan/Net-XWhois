#!/usr/bin/perl
##
## Net::XWhois
## Whois Client Interface Class.
##
## $Date: 2001/07/14 03:18:58 $
## $Revision: 1.2 $
## $State: Exp $
## $Author: vipul $
##
## Copyright (c) 1998, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.

package Net::XWhois;

use Data::Dumper;
use IO::Socket;
use Carp;
use vars qw ( $VERSION $AUTOLOAD );

$VERSION     = '0.80';

my $CACHE    = "/tmp/whois";
my $EXPIRE   = 604800;
my $ERROR    = "croak";
my $TIMEOUT  = 60;

my %PARSERS  = (

 INTERNIC => {
  name            => 'omain Name:\s+(\S+)',
  status          => 'omain Status:\s+(.*?)\s*\n',
  nameservers     => 'in listed order:[\s\n]+(\S+)\s.*?\n\s+(\S*?)\s.*?\n\n',
  registrant      => 'Registrant:\s*\n(.*?)\n\n',
  contact_admin   => 'nistrative Contact.*?\n(.*?)(?=\s*\n[^\n]+?:\s*\n|\n\n)',
  contact_tech    => 'Technical Contact.*?\n(.*?)(?=\s*\n[^\n]+?:\s*\n|\n\n)',
  contact_zone    => 'Zone Contact.*?\n(.*?)(?=\s*\n[^\n]+?:\s*\n|\n\n)',
  contact_billing => 'Billing Contact.*?\n(.*?)(?=\s*\n[^\n]+?:\s*\n|\n\n)',
  contact_emails  => '(\S+\@\S+)',
  contact_handles => '\((\w+\d+)\)',
  domain_handles  => '\((\S*?-DOM)\)',
  org_handles     => '\((\S*?-ORG)\)',
  not_registered  => 'No match',
  forwardwhois    => 'Whois Server: (.*?)(?=\n)',
 },

 RPSL => {
  name            => 'Domain Name\.+:\s(\S+)',
  status          => '(N/A)',
  nameservers     => 'Nameserver Handle\.+:\s(\S+)',
  registrant      => 'Registrar Handle\.+:\s(\S+)',
  contact_admin   => 'Tech-c Handle\.+:\s(\S+)',
  contact_tech    => 'Tech-c Handle\.+:\s(\S+)',
  contact_zone    => 'Zone-c Handle\.+:\s(\S+)',
  contact_billing => 'Bill-c Handle\.+:\s(\S+)',
  contact_emails  => 'Email Address\.+:\s(\S+)',
  contact_handles => '-c Handle\.+:\s(\S+)',
    },

 INTERNIC_CONTACT => {
  name            => '(.+?)\s+\(.*?\)(?:.*?\@)',
  address         => '\n(.*?)\n[^\n]*?\n\n\s+Re',
  email           => '\s+\(.*?\)\s+(\S+\@\S+)',
  phone           => '\n([^\n]*?)\(F[^\n]+\n\n\s+Re',
  fax             => '\(FAX\)\s+([^\n]+)\n\n\s+Re',
 },

 CANADA  => {
  name            => 'domain:\s+(\S+)\n',
  nameservers     => '-Netaddress:\s+(\S+)',
  contact_emails  => '-Mailbox:\s+(\S+\@\S+)',
 },


 RIPE => {
  name            => 'domain:\s+(\S+)\n',
  nameservers     => 'nserver:\s+(\S+)',
  contact_emails  => 'e-mail:\s+(\S+\@\S+)',
  registrants     => 'descr:\s+(.+?)\n',
 },

 RIPE_CH => {
  name            => 'domainname:\s+(\S+)\n',
  nameservers     => 'nserver:\s+(\S+)',
  contact_emails  => 'e-mail:\s+(\S+\@\S+)',
 },

 JAPAN => {
  name            => '\[Domain Name\]\s+(\S+)',
  nameservers     => 'Name Server\]\s+(\S+)',
  contact_emails  => '\[Reply Mail\]\s+(\S+\@\S+)',
 },

 TAIWAN => {
  name            => 'omain Name:\s+(\S+)',
  registrant      => '^(\S+) \(\S+?DOM)',
  contact_emails  => '(\S+\@\S+)',
  nameservers     => 'servers in listed order:[\s\n]+\%see\-also\s+\.(\S+?)\:',
 },

 KOREA  => {
  name            => 'Domain Name\s+:\s+(\S+)',
  nameservers     => 'Host Name\s+:\s+(\S+)',
  contact_emails  => 'E\-Mail\s+:\s*(\S+\@\S+)',
 },

 GENERIC => {
  contact_emails  => '(\S+\@\S+)',
 },


);

my %WHOIS_PARSER = (
    'whois.ripe.net'       => 'RPSL',
    'whois.nic.mil'        => 'INTERNIC',
    'whois.nic.ad.jp'      => 'JAPAN',
    'whois.domainz.net.nz' => 'GENERIC',
    'whois.nic.gov'        => 'INTERNIC',
    'whois.nic.ch'         => 'RIPE_CH',
    'whois.twnic.net'      => 'TAIWAN',
    'whois.internic.net'   => 'INTERNIC',
    'whois.nic.net.sg'     => 'RIPE',
    'whois.aunic.net'      => 'RIPE',
    'whois.cdnnet.ca'      => 'CANADA',
    'whois.nic.uk'         => 'INTERNIC',
    'whois.krnic.net'      => 'KOREA',
    'whois.isi.edu'        => 'INTERNIC',
    'whois.norid.no'       => 'RPSL',
);

my %DOMAIN_ASSOC = (
    'al'  => 'whois.ripe.net',
    'am'  => 'whois.ripe.net',
    'at'  => 'whois.ripe.net',
    'au'  => 'whois.aunic.net',
    'az'  => 'whois.ripe.net',
    'ba'  => 'whois.ripe.net',
    'be'  => 'whois.ripe.net',
    'bg'  => 'whois.ripe.net',
    'by'  => 'whois.ripe.net',
    'ca'  => 'whois.cdnnet.ca',
    'ch'  => 'whois.nic.ch',
    'ch'  => 'whois.ripe.net',
    'com' => 'whois.networksolutions.com',
    'cy'  => 'whois.ripe.net',
    'cz'  => 'whois.ripe.net',
    'de'  => 'whois.ripe.net',
    'dk'  => 'whois.dk-hostmaster.dk',
    'dz'  => 'whois.ripe.net',
    'edu' => 'whois.internic.net',
    'ee'  => 'whois.ripe.net',
    'eg'  => 'whois.ripe.net',
    'es'  => 'whois.ripe.net',
    'fi'  => 'whois.ripe.net',
    'fo'  => 'whois.ripe.net',
    'fr'  => 'whois.ripe.net',
    'gb'  => 'whois.ripe.net',
    'ge'  => 'whois.ripe.net',
    'gov' => 'whois.nic.gov',
    'gr'  => 'whois.ripe.net',
    'hr'  => 'whois.ripe.net',
    'hu'  => 'whois.ripe.net',
    'ie'  => 'whois.ripe.net',
    'il'  => 'whois.ripe.net',
    'is'  => 'whois.ripe.net',
    'it'  => 'whois.ripe.net',
    'jp'  => 'whois.nic.ad.jp',
    'kr'  => 'whois.krnic.net',
    'li'  => 'whois.ripe.net',
    'lt'  => 'whois.ripe.net',
    'lu'  => 'whois.ripe.net',
    'lv'  => 'whois.ripe.net',
    'ma'  => 'whois.ripe.net',
    'md'  => 'whois.ripe.net',
    'mil' => 'whois.nic.mil',
    'mk'  => 'whois.ripe.net',
    'mt'  => 'whois.ripe.net',
    'net' => 'whois.internic.net',
    'nl'  => 'whois.ripe.net',
    'no'  => 'whois.norid.no',
    'nz'  => 'whois.domainz.net.nz',
    'org' => 'whois.internic.net',
    'pl'  => 'whois.ripe.net',
    'pt'  => 'whois.ripe.net',
    'ro'  => 'whois.ripe.net',
    'ru'  => 'whois.ripe.net',
    'se'  => 'whois.ripe.net',
    'sg'  => 'whois.nic.net.sg',
    'si'  => 'whois.ripe.net',
    'sk'  => 'whois.ripe.net',
    'sm'  => 'whois.ripe.net',
    'su'  => 'whois.ripe.net',
    'tn'  => 'whois.ripe.net',
    'tr'  => 'whois.ripe.net',
    'tw'  => 'whois.twnic.net',
    'ua'  => 'whois.ripe.net',
    'uk'  => 'whois.nic.uk',
    'uk'  => 'whois.ripe.net',
    'us'  => 'whois.isi.edu',
    'va'  => 'whois.ripe.net',
    'yu'  => 'whois.ripe.net',
 
);

my %ARGS = (
    'whois.nic.ad.jp'            => { 'S' => '/e' },
    'whois.internic.net'         => { 'P' => '=' },
    'whois.networksolutions.com' => { 'P' => '=' },
);


sub register_parser {

    my ( $self, %args ) = @_;

    $self->{ _PARSERS }->{ $args{ Name } } = {} unless $args{ Retain };
    for ( keys %{ $args{ Parser } } ) {
        $self->{ _PARSERS }->{ $args{ Name } }->{$_} = $args{ Parser }->{$_};
    }

    return 1;

}


sub register_association {

    my ( $self, %args ) = @_;
    foreach my $server ( keys %args ) {
        # Update our table for looking up the whois server => parser
        $self->{ _WHOIS_PARSER }->{ $server } = $args{ $server }->[0];  # Save name of whois server and associated parser
        # Update our table of domains and their associated server
        $self->{ _DOMAIN_ASSOC }->{ $_ } = $server for ( @{$args{ $server }}->[1]);
    };

    return 1;

}


sub register_cache {

    my ( $self, $cache ) = @_;
    return ${ $self->{ _CACHE } } = $cache  if $cache;

}


sub server {
     my $self = shift;
     return $self->{ Server };

}


sub guess_server_details {

    my ( $self, $domain ) = @_;
    $domain = lc $domain;

    my ( $server, $parser );
    my ( $Dserver, $Dparser ) =
       ( 'whois.internic.net', { %{ $self->{ _PARSERS }->{ INTERNIC } } } );

    $domain =~ s/.*\.(\w+)$/$1/;
    $server = $self->{ _DOMAIN_ASSOC }->{ $domain };
    $parser = $self->{ _PARSERS }->{ $self->{ _WHOIS_PARSER }->{ $server } } if ($server);

    return $server ? [$server, $parser] : [$Dserver, $Dparser];

};


sub new {

    my ( $class, %args ) = @_;

    my $self = {};
    $self->{ _PARSERS } = \%PARSERS;
    $self->{ _DOMAIN_ASSOC } = \%DOMAIN_ASSOC;
    $self->{ _WHOIS_PARSER } = \%WHOIS_PARSER;
    $self->{ _CACHE }   = $args{Cache}   || \$CACHE;
    $self->{ _EXPIRE }  = $args{Expire}  || \$EXPIRE;
    $self->{ _ARGS }    = \%ARGS;

    bless $self, $class;

    $self->personality ( %args );
    $self->lookup () if $self->{ Domain };
    return $self;

}


sub personality {

    my ( $self, %args ) = @_;

    for ( keys %args ) { chomp $args{ $_}; $self->{ $_ } = $args{ $_ } }
    $self->{ Parser } = $self->{ _PARSERS }->{ $args{ Format } }
                        if $args{ Format };

    unless ( $self->{ Server } ) {
        my $res = $self->guess_server_details ( $self->{ Domain } );
        ( $self->{ Server }, undef ) = @$res;
    }

    unless ( $self->{ Parser } &&  $self->{ Format } ) {
        my $res = $self->guess_server_details ( $self->{ Domain } );
        ( undef, $self->{ Parser } ) = @$res;
    }

    $self->{ Timeout } = $TIMEOUT unless $self->{ Timeout };
    $self->{ Error }   = $ERROR unless $self->{ Error };

}


sub lookup {

    my ( $self, %args ) = @_;

    $self->personality ( %args );

    my $cache = $args{ Cache } || ${ $self->{ _CACHE } };
    my $domain = $self->{ Domain };

    unless ( $self->{ Nocache } ) {
    READCACHE: {
        if ( -d $cache ) {
            last READCACHE unless -e "$cache/$domain";
            my $current = time ();
            open D, "$cache/$domain" || last READCACHE;
            my @stat = stat ( D );
            if ( $current - $stat[ 9 ] > ${ $self->{ _EXPIRE } } ) {
                close D;
                last READCACHE;
            }
            undef $/; $self->{ Response } = <D>;
            return 1;
        }
    }
    }

    my $server = $self->{ Server };
    my $suffix = $self->{ _ARGS }->{ $server }->{S} || '';
    my $prefix = $self->{ _ARGS }->{ $server }->{P} || '';
    my $sock = $self->_connect ( $self->{ Server } );
    return undef unless $sock;
    print $sock $prefix , $self->{ Domain }, "$suffix\r\n";
    { local $/; undef $/; $self->{  Response  } = <$sock>; }
    undef $sock;

    my $fw = eval { $self->forwardwhois };
    my @fwa = ();
    if ($fw =~ m/\n/) {
        @fwa = $self->{ Response } =~
        m/\s+$self->{ Domain }\n.*?\n*?\s*?.*?Whois Server: (.*?)(?=\n)/isg;
        $fw = shift @fwa;
        return undef unless (length($fw) > 0); # pattern not found
        return undef if ($self->{ Server } eq $fw); #avoid infinite loop
    }
    if ( $fw ne "" ) {
        $self->personality( Format => $self->{_WHOIS_PARSER}->{$fw});
        return undef if ($self->{ Server } eq $fw); #avoid infinite loop
        $self->{ Server } = $fw; $self->{ Response } = "";
        $self->lookup();
    }

    if ( (-d $cache) && (!($self->{Nocache})) ) {
        open D, "> $cache/$domain" || return;
        print D $self->{ Response };
        close D;
    }

}


sub AUTOLOAD {

    my $self = shift;

    return undef unless $self->{ Response };
    my $key = $AUTOLOAD; $key =~ s/.*://;
    croak "Method $key not defined." unless exists ${$self->{ Parser }}{$key};

    my @matches = ();

    if ( ref(${$self->{ Parser } }{ $key }) !~ /^CODE/  ) {
    @matches = $self->{ Response } =~ /${ $self->{ Parser } }{ $key }/sg;
    } else {
        @matches = &{ $self->{ Parser }{$key}}($self->response);
    }

    my @tmp = split /\n/, join "\n", @matches;
    for (@tmp) { s/^\s+//; s/\s+$//; chomp };

    return wantarray ? @tmp :  join "\n", @tmp ;

}


sub response {

    my $self = shift;
    return $self->{ Response };

}


sub _connect {

    my $self = shift;
    my $machine = shift;
    my $error = $self->{Error};

    my $sock = new IO::Socket::INET PeerAddr => $machine,
                                    PeerPort => 'whois',
                                    Proto    => 'tcp',
                                    Timeout  => $self->{Timeout}
       or &$error( "[$@]" );

    $sock->autoflush if $sock;
    return $sock;

}


sub ignore {}


'True Value.';


=head1 NAME

Net::XWhois - Whois Client Interface for Perl5.

=head1 SYNOPSIS

 use Net::XWhois;

 $whois = new Net::XWhois Domain => "vipul.net" ;
 $whois = new Net::XWhois Domain => "bit.ch",
                          Server => "domreg.nic.ch",
                          Retain => 1,
                          Parser => {
                             nameservers => 'nserver:\s+(\S+)',
                          };

=head1 DESCRIPTION

The Net::XWhois class provides a generic client framework for doing Whois
queries and parsing server response.

The class maintains an array of top level domains and whois servers
associated with them. This allows the class to transparently serve
requests for different tlds, selecting servers appropriate for the tld.
The server details are, therefore, hidden from the user and "vipul.net"
(from InterNIC), gov.ru (from RIPE) and "bit.ch" (from domreg.nic.ch) are
queried in the same manner. This behaviour can be overridden by specifying
different bindings at object construction or by registering associations
with the class. See L<"register_associations()"> and L<"new()">.

One of the more important goals of this module is to enable the design of
consistent and predictable interfaces to incompatible whois response
formats. The Whois RFC (954) does not define a template for presenting
server data; consequently there is a large variation in layout styles as
well as content served across servers.

(There is, however, a new standard called RPSL (RFC2622) used by RIPE
(http://www.ripe.net), the European main whois server.)

To overcome this, Net::XWhois maintains another set of tables - parsing
rulesets - for a few, popular response formats. (See L<"%PARSERS">). These
parsing tables contain section names (labels) together with regular
expressions that I<match> the corresponding section text. The section text
is accessed "via" labels which are available as data instance methods at
runtime. By following a consistent nomenclature for labels, semantically
related information encoded in different formats can be accessed with the
same methods.

=head1 CONSTRUCTOR

=over 4

=item new ()

Creates a Net::XWhois object. Takes an optional argument, a hash, that
specifies the domain name to be queried. Calls lookup() if a name is
provided. The argument hash can also specify a whois server, a parsing
rule-set or a parsing rule-set format. (See L<"personality()">). Omitting
the argument will create an "empty" object that can be used for accessing
class data.

=item personality ()

Alters an object's personality.  Takes a hash with following arguments.
(Note: These arguments can also be passed to the constructor).

=over 8

=item B<Domain>

Domain name to be queried.

=item B<Server>

Server to query.

=item B<Parser>

Parsing Rule-set.  See L<"%PARSERS">.

 Parser => {
   name            => 'domain:\s+(\S+)\n',
   nameservers     => 'nserver:\s+(\S+)',
   contact_emails  => 'e-mail:\s+(\S+\@\S+)',
 };


=item B<Format>

A pre-defined parser format like INTERNIC, INTERNIC_FORMAT, RIPE,
RIPE_CH, JAPAN etc.

 Format => 'INTERNIC_CONTACT',

=item B<Nocache>

Force XWhois to ignore the cached records.

=item B<Error>

Determines how a network connection error is handled. By default Net::XWhois
will croak() if it can't connect to the whois server. The Error attribute
specifies a function call name that will be invoked when a network
connection error occurs. Possible values are croak, carp, confess (imported
from Carp.pm) and ignore (a blank function provided by Net::XWhois). You
can, of course, write your own function to do error handling, in which case
you'd have to provide a fully qualified function name. Example:
main::logerr.

=item B<Timeout>

Timeout value for establishing a network connection with the server. The
default value is 60 seconds.

=back

=back

=head1 CLASS DATA & ACCESS METHODS

=over 4

=item %PARSERS

An associative array that contains parsing rule-sets for various response
formats.  Keys of this array are format names and values are hash refs that
contain section labels and corresponding parser code.  The parser code can
either be a regex or a reference to a subroutine.  In the case of a
subroutine, the whois 'response' information is available to the sub in
$_[0].  Parsers can be added and extended with the register_parser() method.
Also see L<Data Instance Methods>.

  my %PARSERS  = (
   INTERNIC => {
    contact_tech    => 'Technical Contact.*?\n(.*?)(?=\...
    contact_zone    => 'Zone Contact.*?\n(.*?)(?=\s*\n[...
    contact_billing => 'Billing Contact.*?\n(.*?)(?=\s*...
    contact_emails  => \&example_email_parser
  },
  { etc. ... },
 );

 sub example_email_parser {

     # Note that the default internal implemenation for
     # the INTERNIC parser is not a user-supplied code
     # block.  This is just an instructive example.

     my @matches = $_[0] =~ /(\S+\@\S+)/sg;
     return @matches;
 }

See XWhois.pm for the complete definition of %PARSERS.

=item %WHOIS_PARSER

%WHOIS_PARSER is a table that associates each whois server with their output format.

    my %WHOIS_PARSER = (
    'whois.ripe.net'       => 'RPSL',
    'whois.nic.mil'        => 'INTERNIC',
    'whois.nic.ad.jp'      => 'JAPAN',
    'whois.domainz.net.nz' => 'GENERIC',
    'whois.nic.gov'        => 'INTERNIC',
    'whois.nic.ch'         => 'RIPE_CH',
    'whois.twnic.net'      => 'TAIWAN',
    'whois.internic.net'   => 'INTERNIC',
    'whois.nic.net.sg'     => 'RIPE',
    'whois.aunic.net'      => 'RIPE',
    'whois.cdnnet.ca'      => 'CANADA',
    'whois.nic.uk'         => 'INTERNIC',
    'whois.krnic.net'      => 'KOREA',
    'whois.isi.edu'        => 'INTERNIC',
    'whois.norid.no'       => 'RPSL',
        ( etc.....)

Please note that there is a plethora of output formats, allthough there
are RFCs on this issue, like for instance RFC2622, there are numerous
different formats being used!

=item %DOMAIN_ASSOC

%DOMAIN_ASSOC is a table that associates top level domain names with their
respective whois servers. You'd need to modity this table if you wish to
extend the module's functionality to handle a new set of domain names. Or
alter existing information. I<register_association()> provides an
interface to this array. See XWhois.pm for the complete definition.

    my %DOMAIN_ASSOC = (
    'al' => 'whois.ripe.net',
    'am' => 'whois.ripe.net',
    'at' => 'whois.ripe.net',
    'au' => 'whois.aunic.net',
    'az' => 'whois.ripe.net',
    'ba' => 'whois.ripe.net',
    'be' => 'whois.ripe.net',


=item register_parser()

Extend, modify and override entries in %PARSERS. Accepts a hash with three
keys - Name, Retain and Parser. If the format definition for the specified
format exists and the Retain key holds a true value, the keys from the
specified Parser are added to the existing definition. A new definition is
created when Retain is false/not specified.

 my $w = new Net::Whois;
 $w->register_parser (
    Name   => "INTERNIC",
    Retain => 1,
    Parser => {
        creation_time => 'created on (\S*?)\.\n',
        some_randome_entity => \&random_entity_subroutine
    };

Instructions on how to create a workable random_entity_subroutine are
availabe in the I<%PARSERS> description, above.

=item register_association()

Override and add entries to %ASSOC. Accepts a hash that contains
representation specs for a whois server. The keys of this hash are server
machine names and values are list-refs to the associated response formats
and the top-level domains handled by the servers. See Net/XWhois.pm for
more details.

 my $w = new Net::XWhois;
 $w->register_association (
     'whois.aunic.net' => [ RIPE, [ qw/au/ ] ]
 );

=item register_cache()

By default, Net::XWhois caches all whois responses and commits them, as
separate files, to /tmp/whois.  register_cache () gets and sets the cache
directory. Setting to "undef" will disable caching.

 $w->register_cache ( "/some/place/else" );
 $w->register_cache ( undef );

=back

=head1 OBJECT METHODS

=over 4

=item B<Data Instance Methods>

Access to the whois response data is provided via AUTOLOADED methods
specified in the Parser. The methods return scalar or list data depending
on the context.


Internic Parser provides the following methods:

=over 8

=item B<name()>

Domain name.

=item B<status()>

Domain Status when provided.  When the domain is on hold, this
method will return "On Hold" string.

=item B<nameservers()>

Nameservers along with their IPs.

=item B<registrant>

Registrant's name and address.

=item B<contact_admin()>

Administrative Contact.

=item B<contact_tech()>

Technical Contact.

=item B<contact_zone()>

Zone Contact.

=item B<contact_billing()>

Billing Contact.

=item B<contact_emails()>

List of email addresses of contacts.

=item B<contact_handles()>

List of contact handles in the response.  Contact and Domain handles
are valid query data that can be used instead of contact and domain
names.

=item B<domain_handles()>

List of domain handles in the response.   Can be used for sorting
out reponses that contain multiple domain names.

=back

=item B<lookup()>

Does a whois lookup on the specified domain.  Takes the same arguments as
new().

 my $w = new Net::XWhois;
 $w->lookup ( Domain => "perl.com" );
 print $w->response ();

=back

=head1 EXAMPLES

Look at example programs that come with this package. "whois" is a
replacement for the standard RIPE/InterNIC whois client. "creation"
overrides the Parser value at object init and gets the Creation Time of an
InterNIC domain. "creation2" does the same thing by extending the Class
Parser. "contacts" queries and prints information about domain's
Tech/Billing/Admin contacts.

contribs/ containts parsers for serveral whois servers, which have not been
patched into the module.

=head1 AUTHOR

Vipul Ved Prakash <mail@vipul.net>

=head1 THANKS

Curt Powell <curt.powell@sierraridge.com>, Matt Spiers
<matt@pavilion.net>, Richard Dice <rdice@pobox.com>, Robert Chalmers
<robert@chalmers.com.au>, Steinar Overbeck Cook <steinar@balder.no> for
patches, bug-reports and many cogent suggestions.

=head1 MAILING LIST

Net::XWhois development has moved to the sourceforge mailing list,
xwhois-devel@lists.sourceforge.net.  Please send all Net::XWhois related
communication directly to the list address.  The subscription interface is
at: http://lists.sourceforge.net/mailman/listinfo/xwhois-devel

=head1 SEE ALSO

 RFC 954  <http://www.faqs.org/rfcs/rfc954.html>
 RFC 2622 <http://www.faqs.org/rfcs/rfc2622.html>

=head1 COPYRIGHT

Copyright (c) 1998-2001 Vipul Ved Prakash. All rights reserved. This
program is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.
