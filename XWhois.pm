#!/usr/bin/perl
##
## Net::XWhois 
## Whois Client Interface Class. 
##
## $Date: 2000/07/09 05:37:20 $
## $Revision: 0.67 $
## $State: Exp $
## $Author: root $
##
## Copyright (c) 1998, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.

package Net::XWhois; 

use IO::Socket; 
use Carp; 
use vars qw ( $VERSION $AUTOLOAD ); 

( $VERSION )  = '$Revision: 0.67 $' =~ /\s+(\d+\.\d+)\s+/; 

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

my %ASSOC = (   
 'whois.internic.net'   => [ "INTERNIC",  [ qw/com net org/ ] ],
 'whois.nic.gov'        => [ "INTERNIC",  [ qw/gov/ ] ],
 'whois.isi.edu'        => [ "INTERNIC",  [ qw/us/  ] ],
 'whois.nic.net.sg'     => [ "RIPE",      [ qw/sg/  ] ],
 'whois.aunic.net'      => [ "RIPE",      [ qw/au/  ] ],  
 'whois.nic.ch'         => [ "RIPE_CH",   [ qw/ch/  ] ], 
 'whois.nic.uk'         => [ "INTERNIC",  [ qw/uk/  ] ], 
 'whois.nic.ad.jp'      => [ "JAPAN",     [ qw/jp/  ] ], 
 'whois.twnic.net'      => [ "TAIWAN",    [ qw/tw/  ] ], 
 'whois.krnic.net'      => [ "KOREA",     [ qw/kr/  ] ], 
 'whois.domainz.net.nz' => [ "GENERIC",   [ qw/nz/  ] ],
 'cdnnet.ca'            => [ "CANADA",    [ qw/ca/  ] ],
 'whois.ripe.net'       => [ "RIPE",      [ 
                        qw( al am at az      ma md mk mt  
                            ba be bg by      nl no        
                            ch cy cz         pl pt        
                            de dk dz         ro ru        
                            ee eg es         se si sk sm su 
                            fi fo fr         tn tr 
                            gb ge gr         ua uk
                            hr hu ie         va
                            il is it         yu
                            li lt lu lv 
                          ) ] ], 
);


my %ARGS = (
    'whois.nic.ad.jp' => '/e',
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
    for ( keys %args ) { $self->{ _ASSOC }->{ $_ } = $args{ $_ } };
    return 1; 

}


sub register_cache { 

    my ( $self, $cache ) = @_; 
    return ${ $self->{ _CACHE } } = $cache  if $cache;

}


sub guess_server_details { 

    my ( $self, $domain ) = @_;
    $domain =~ y/A-Z/a-z/;

    my ( $server, $parser ); 
    my ( $Dserver, $Dparser ) = 
       ( 'whois.internic.net', { %{ $self->{ _PARSERS }->{ INTERNIC } } } );

    SWITCH: for ( keys %{ $self->{ _ASSOC } } ) { 
        if ( grep { $domain =~ m/\.$_$/ } @{ $self->{ _ASSOC }->{ $_ }[1] } ) { 
            $server = $_; 
            $parser = $self->{ _PARSERS }->{ $self->{ _ASSOC }->{ $_ }[0] };
            last SWITCH; 
         }
     }

    return $server ? [$server, $parser] : [$Dserver, $Dparser]; 

};


sub new { 

    my ( $class, %args ) = @_; 

    my $self = {}; 
    $self->{ _PARSERS } = \%PARSERS; 
    $self->{ _ASSOC }   = \%ASSOC; 
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

    unless ( $self->{ Parser }  &&  $self->{ Format } ) { 
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
    my $args = $self->{ _ARGS }->{ $server }; 
    my $sock = $self->_connect ( $self->{ Server } ); 
    return undef unless $sock;
    print $sock $self->{ Domain }, "$args\r\n"; 
    my $jump = $/;
    { undef $/; $self->{  Response  } = <$sock>; }  
    $/ = $jump;
    undef $sock;

    my $fw = eval { $self->forwardwhois };
    if ( $fw ne "" ) { 
        $self->{ Server } = $fw; $self->{ Response } = "";
        $self->lookup(); 
    }

    if ( -d $cache ) { 
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

    my @matches = $self->{ Response } =~ /${ $self->{ Parser } }{ $key }/sg; 
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

The class maintains an array of whois servers and associated lists of top level 
domains they serve for transparently selecting servers appropriate 
for different queries.  The server details are, therefore, hidden from the 
user and "vipul.net" (from InterNIC), gov.ru (from RIPE) and "bit.ch" (from 
domreg.nic.ch) are queried in the same manner.  This behaviour 
can be overridden by specifying different bindings at object construction or 
by registering associations with the class.  See L<"register_associations()"> 
and L<"new()">. 

One of the more important features of this module is to enable the design of 
consistent and predictable interfaces to incompatible whois response formats. 
The Whois RFC (954) does not define a template for presenting server data; 
consequently there is a large variation in layout styles as well as content 
served across servers. 

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

Creates a Net::XWhois object.  Takes an optional argument, a hash, that
specifies the domain name to be queried.  Calls lookup() if a name
is provided. The argument hash can also specify a whois server, a parsing 
rule-set or a parsing rule-set format. (See L<"personality()">).  Omitting 
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
contain section labels and corresponding regex masks.  Parsers can be added and 
extended with the register_parser() method.  Also see L<Data Instance Methods>.

 my %PARSERS  = ( 
  INTERNIC => {    
   name            => 'omain Name:\s+(\S+)', 
   nameservers     => 'order:[\s\n]+(.*?)\n\s+(.*?)\n\n', 
   registrant      => 'Registrant:\s*\n(.*?)\n\n',  
   contact_admin   => 've Contact.*?\n(.*?)(?=\s*\n[^\...
   contact_tech    => 'Technical Contact.*?\n(.*?)(?=\...
   contact_zone    => 'Zone Contact.*?\n(.*?)(?=\s*\n[...
   contact_billing => 'Billing Contact.*?\n(.*?)(?=\s*...
   contact_emails  => '(\S+\@\S+)', 
  },  

See XWhois.pm for the complete definition of %PARSERS. 

=item %ASSOC

%ASSOC is a table that associates server names with response formats and the 
top-level domains they serve.  You'd need to modity this table if you wish to
extend the module's functionality to handle a new set of domain names.  Or 
alter existing information.   register_association() provides an interface 
to this array.  See XWhois.pm for the complete definition. 

 %ASSOC = (
  'whois.internic.net' => 
        [ INTERNIC,  [ qw/com net org/ ] ],
  'whois.nic.net.sg'   => 
        [ RIPE,      [ qw/sg/ ] ],
  'whois.aunic.net'    => 
        [ RIPE,      [ qw/au/ ] ]


=item register_parser() 

Extend, modify and override entries in %PARSERS. Accepts a hash with three keys 
- Name, Retain and Parser.  If the format definition for the specified format 
exists and the Retain key holds a true value, the keys from the specified Parser 
are added to the existing definition. A new definition is created when Retain is 
false/not specified. 

 my $w = new Net::Whois;
 $w->register_parser ( 
    Name   => "INTERNIC", 
    Retain => 1, 
    Parser => { 
        creation_time => 'created on (\S*?)\.\n', 
    }; 



=item register_association() 

Override and add entries to %ASSOC.  Accepts a hash that contains 
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
specified in the Parser.  The methods return scalar or list data depending 
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

Look at example programs that come with this package. "whois" is a replacement
for the standard RIPE/InterNIC whois client. "creation" overrides the Parser 
value at object init and gets the Creation Time of an InterNIC domain. 
"creation2" does the same thing but by extending the Class Parser instead.
"contacts" queries and prints information about domain's Tech/Billing/Admin 
contacts.  

=head1 AUTHOR

Vipul Ved Prakash <mail@vipul.net>

=head1 COPYRIGHT

Copyright (c) 1998 Vipul Ved Prakash.  All rights reserved. This program is 
free software; you can redistribute it and/or modify it under the same terms 
as Perl itself. 


