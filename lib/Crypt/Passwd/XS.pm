package Crypt::Passwd::XS;

our $VERSION = '0.4';

require XSLoader;
XSLoader::load( 'Crypt::Passwd::XS', $VERSION );

sub crypt {
    my $password = shift;
    my $salt = shift;
    return unless $salt;
    my $crypt_type = substr($salt,0,3);
    if ($crypt_type eq '$1$') {
        return unix_md5_crypt($password, $salt);
    }
    elsif ( $crypt_type eq '$6$' ) {
        return unix_sha512_crypt($password, $salt);
    }
    elsif ( $crypt_type eq '$5$' ) {
        return unix_sha256_crypt($password, $salt);
    }
    elsif (substr($salt,0,1) ne '$' ) {
        return unix_des_crypt($password, $salt);
    }
    else {
        # Unimplemented hashing scheme
        return;
    }
}

1;

__END__
