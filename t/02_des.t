use strict;
use warnings;

use Test::More 'tests' => 9;
use Crypt::Passwd::XS ();

my $checks = [
    [ 'test1234', 'test1234', 'tesvSclXGCVNk' ],
    [ 'test1234', 'aa',       'aaGUTMncdkeWY' ],
    [ 'test1234', 'bb',       'bbO19gCe57B0E' ],
    [ 'test1234', 'a',        'aaGUTMncdkeWY' ],
    [ 'test1234', 'b',        'bbO19gCe57B0E' ],
    [ 'test1234', '',         '' ],
    [ '',         'aa',       'aaQSqAReePlq6' ],
    [ 'test1234', undef,      '' ],
    [ undef,      'aa',       'aaQSqAReePlq6' ],
];

foreach my $check_ref (@$checks) {
    my $pass    = $check_ref->[0];
    my $salt    = $check_ref->[1];
    my $crypted = $check_ref->[2];
    my $result  = Crypt::Passwd::XS::unix_des_crypt( $pass, $salt );
    is( $result, $crypted, q{Hashed with pass:} . ( defined $pass ? qq{"$pass"} : q{(undef)} ) . q{ salt:} . ( defined $salt ? qq{"$salt"} : q{(undef)} ) );
}
