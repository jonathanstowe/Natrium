#!/usr/bin/env perl6

use v6;

use Test;

use Natrium;

my $t = Natrium.new;

my Int $val;

lives-ok { $val = $t.randombytes() }, "randombytes no args";

lives-ok { $val = $t.randombytes(upper-bound => 512) }, "randombytes with upper-bound";

ok $val ≤ 512, "and it is within the bound";

my Buf $buf;

#
lives-ok { $buf = $t.randombytes(buf => $t.keybytes) }, "randombytes with buf";

is $buf.bytes, $t.keybytes, "got the right number of bytes";

done-testing;
# vim: ft=perl6
