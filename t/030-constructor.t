#!/usr/bin/env perl6

use Test;

use Natrium;

lives-ok { my $t = Natrium.new }, "Natrium constructor";

lives-ok { my $t = Natrium.new }, "Natrium constructor (again to make sure it can handle init being run twice)";


done-testing();

# vim: ft=perl6
