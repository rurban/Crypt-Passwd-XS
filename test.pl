# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

BEGIN {print "1..2\n";}
END {print "not ok 1\n" unless $loaded;}
use Crypt::Passwd::XS;
$loaded = 1;
print "ok 1\n";

my $pass = Crypt::Passwd::XS::unix_md5_crypt("fds" x 31, 'gdf' x 543);
$pass =~ /\S+/ or print 'not ';
print "ok 2 ($pass)\n";

my $pass2 = Crypt::Passwd::XS::unix_md5_crypt("fds" x 31, '$1$' .  'gdf' x 543);
$pass eq $pass2 or print 'not ';
print "ok 3 ($pass2)\n";
