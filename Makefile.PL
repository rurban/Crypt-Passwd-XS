use ExtUtils::MakeMaker;
use Config;

my %CFG = (
        'VERSION_FROM' => 'lib/Crypt/PasswdMD5/XS.pm',
	'NAME'		=> 'Crypt::PasswdMD5::XS',
        'INSTALLDIRS' => 'site'  

    );

my $salt = crypt('crypt_test','$1$SALTSALT');
if (substr($salt,0,12) eq '$1$SALTSALT$') {
	print "Using built in crypt()\n";
        system 'install','-m0644','tpl/perlcrypt/XS.pm','lib/Crypt/PasswdMD5/XS.pm';
	$CFG{'XS'} = {};	
	$CFG{'C'} = [];
} else {
        system 'install','-m0644','tpl/xscrypt/XS.pm','lib/Crypt/PasswdMD5/XS.pm';
	print "Building XS crypt()\n";
}

WriteMakefile(%CFG);
