use strict;
use warnings;

use Test::More 'tests' => 3;
use Crypt::Passwd::XS ();

my $checks = [ [ 'test1234', 'test1234', 'tesvSclXGCVNk' ], [ 'test1234', 'aa', 'aaGUTMncdkeWY' ], [ 'test1234', 'bb', 'bbO19gCe57B0E' ] ];

foreach my $check_ref (@$checks) {
    my $crypted = Crypt::Passwd::XS::unix_des_crypt( $check_ref->[0], $check_ref->[1] );
    ok( $crypted eq $check_ref->[2], "Hashed des password matched" );
}
