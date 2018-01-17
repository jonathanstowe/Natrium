#!/usr/bin/env perl6

use Test;

use Natrium;

my $t = Natrium.new;

my Str $str = "Test String";

my $buf1;

lives-ok { $buf1 = $t.generichash($str) }, "generichash with string";

my $buf2;

lives-ok { $buf2 = $t.generichash($str.encode) }, "generichash with buf";

cmp-ok $buf1, 'eqv', $buf2, "got the same hash";

cmp-ok $t.generichash("SOmething completely different"), &[!eqv], $buf1, "hash of a different string differs";

done-testing();

# vim: ft=perl6
