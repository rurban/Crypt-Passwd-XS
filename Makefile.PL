use ExtUtils::MakeMaker;
use Config;

my %CFG = (
        'VERSION_FROM' => 'lib/Crypt/Passwd/XS.pm',
	'NAME'		=> 'Crypt::Passwd::XS',
        'INSTALLDIRS' => 'site',
        'OBJECT' => "sha256crypt.o des.o md5.o md5crypt.o XS.o",
    );

WriteMakefile(%CFG);
