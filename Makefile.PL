#!/usr/bin/perl -sw
##
## Makefile.PL for Net::XWhois.
##
## $Date: 1998/12/15 22:01:55 $
## $Revision: 0.10 $
## $State: Exp $
## $Author: root $
##
## Copyright (c) 1998, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.

use ExtUtils::MakeMaker;

my @clean = qw(*% *.html *.b[ac]k *.old *gz);
push @clean, map { "*/$_" } @clean;

WriteMakefile(

    'VERSION_FROM' => 'XWhois.pm',
    'NAME'         => 'Net::XWhois', 
     
    'dist'         => {      
                         COMPRESS => 'gzip -9f',
                         SUFFIX   => '.gz',
                         DIST_DEFAULT => 'all tardist',
                      },

     'clean'       => { FILES => join ( " ", @clean ) },
);                                                     

