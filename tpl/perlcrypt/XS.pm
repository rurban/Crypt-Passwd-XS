package Crypt::PasswdMD5::XS;

our $VERSION = '0.3';

require Exporter;

our @ISA = qw(Exporter);
our @EXPORT = (); 
our @EXPORT_OK = qw(unix_md5_crypt);

sub unix_md5_crypt {
	my($pw,$salt) = @_;

	if (substr( $salt,0,3) ne '$1$') {
		$salt = '$1$'. $salt;
	}
	return crypt($pw,$salt);
}

1;

__END__
