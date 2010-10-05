use ExtUtils::MakeMaker;
use Config;

my %CFG = (
        'VERSION_FROM' => 'lib/Crypt/PasswdMD5/XS.pm',
	'NAME'		=> 'Crypt::PasswdMD5::XS',
        'INSTALLDIRS' => 'site',
        'OBJECT' => "md5.o md5crypt.o XS.o",
    );

WriteMakefile(%CFG);
