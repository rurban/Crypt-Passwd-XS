package Crypt::PasswdMD5::XS;

our $VERSION = '0.3';

use XSLoader ();
require Exporter;

our @ISA = qw(Exporter);
our @EXPORT = (); 
our @EXPORT_OK = qw(unix_md5_crypt);

XSLoader::load ('Crypt::PasswdMD5::XS', $VERSION);

1;

__END__
