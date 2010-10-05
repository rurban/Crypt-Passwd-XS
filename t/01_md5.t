use strict;
use warnings;

use Test::More 'tests' => 2;
use Crypt::Passwd::XS ();

my $checks = [
   [ 'test1234', 'test1234', '$1$test1234$0BvsB10tWW2oD4p7fanjN.' ],
   [ 'test1234', '', '$1$$a/H3O7Gxc.2w21w4XZrCJ0' ],
];

foreach my $check_ref (@$checks) {
    my $crypted = Crypt::Passwd::XS::unix_md5_crypt( $check_ref->[0], $check_ref->[1] );
    ok( $crypted eq $check_ref->[2], "Hashed md5 password matched" );
}
