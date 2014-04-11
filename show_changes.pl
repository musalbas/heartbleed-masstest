#! /usr/bin/env perl

use strict;
use warnings;
use autodie;
use Data::Dumper;
use feature qw(say);

use constant
   FILES        => qw( top1000.txt  top10000-10-Apr-14-2000UTC.txt );

use constant
   HEADINGS     => qw( Website  04/08/2014 04/10/2014 );

use constant {
    OUTPUT_FILE => qq(changes.md),
    FORMAT      => qq(| %-20.20s | %-20.20s |  %-20.20s | \n),
    TEST_LINE   => qr/^Testing\s+(\S+)\.\.\.\s+(.*)/,
};


my %websites;
my $on_first_file = 1;
for my $file ( FILES ) {
    open my $file_fh, "<", $file;
    while ( my $line = <$file_fh> ) {
        chomp $line;
        next unless $line =~ /^Testing\s+(\S+)\.\.\.\s+(.*)/;
        my $website = $1;
        my $status = $2;
        $websites{$website}->{$file} = $status;
    }
    $on_first_file = 0;
    close $file_fh;
}

#
# Report
#

open my $output_fh, ">", OUTPUT_FILE;

printf {$output_fh} FORMAT, HEADINGS;
say {$output_fh} ( "|" . "-" x 22 ) x HEADINGS . "-|";
WEBSITE:
for my $website ( sort keys %websites ) {
    my $original_status;
    my @statuses;
    FILE:
    for my $file ( FILES ) {
        if ( not $original_status ) { # Skip site if not in first file
            next WEBSITE if not exists $websites{$website}->{$file};
            $original_status = $websites{$website}->{$file};
        }
        if ( exists $websites{$website}->{$file} ) {
            push @statuses, $websites{$website}->{$file};
        }
        else {
            push @statuses, "N/A";
        }
    }
    next WEBSITE if $statuses[0] eq $statuses[-1];
    printf {$output_fh} FORMAT, $website, @statuses;
}

=pod

=head1 NAME

show_changes.pl

=head1 SYNOPSIS

    $ show_changes.pl

=head1 DESCRIPTION

This program takes the various I<reports> produced by the scans and
puts them together into one report showing the changes taking place
since the first report.

Reports are hardcoded into the program. (I'm too lazy to setup 
Getopts::Long) so there is nothing to enter. Basically, only the
websites were the first report and last report have differenecs show
up in this report.

You can setup the various files and report headings by modifying the
I<constants> at the top of the program.

=head1 AUTHOR

David Weintraub <david@weintraub.name>

=head1 LICENSE

You are not allowed to use this for evil purposes such as taking over
and ruling the world. Beyond that, feel free to use this however you want.
