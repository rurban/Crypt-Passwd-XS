use strict;
use warnings;

use Test::More 'tests' => 7;
use Crypt::Passwd::XS ();

my $checks = [
    [ 'Hello world!',        '$6$saltstring',                        '$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1' ],
    [ 'Hello world!',        '$6$rounds=10000$saltstringsaltstring', '$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.' ],
    [ 'This is just a test', '$6$rounds=5000$toolongsaltstring',     '$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0' ],
    [
        'a very much longer text to encrypt.  This one even stretches over morethan one line.', '$6$rounds=1400$anotherlongsaltstring',
        '$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1'
    ],
    [ 'we have a short salt string but not a short password', '$6$rounds=77777$short', '$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0' ],
    [ 'a short string', '$6$rounds=123456$asaltof16chars..', '$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1' ],
    [ 'the minimum number is still observed', '$6$rounds=10$roundstoolow', '$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX.' ],
];

foreach my $check_ref (@$checks) {
    my $crypted = Crypt::Passwd::XS::unix_sha512_crypt( $check_ref->[0], $check_ref->[1] );
    ok( $crypted eq $check_ref->[2], " Hashed sha512 password matched " );
}
