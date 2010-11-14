/*-
 * Copyright (c) 2010 cPanel, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the same terms as Perl itself, either Perl version 5.10.1 or,
 * at your option, any later version of Perl 5 you may have available.
 */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "md5crypt.h"
#include "des.h"
#include "sha256crypt.h"
#include "sha512crypt.h"

MODULE = Crypt::Passwd::XS PACKAGE = Crypt::Passwd::XS

PROTOTYPES: ENABLE

SV*
unix_md5_crypt(pw,salt)
	SV *pw;
	SV *salt; 

	INIT:
		char *cryptpw = NULL;
        	RETVAL = &PL_sv_undef;
	
	CODE:
		cryptpw = crypt_md5( SvPVX(pw), SvPVX(salt) );
		if (cryptpw != NULL) {
			RETVAL = newSVpv(cryptpw,0);
		}

	OUTPUT:
		RETVAL

SV*
unix_des_crypt(pw,salt)
	SV *pw;
	SV *salt; 

	INIT:
		char *cryptpw = NULL;
        	RETVAL = &PL_sv_undef;
	
	CODE:
		cryptpw = crypt_des( SvPVX(pw), SvPVX(salt) );
		if (cryptpw != NULL) {
			RETVAL = newSVpv(cryptpw,0);
		}

	OUTPUT:
		RETVAL

SV*
unix_sha256_crypt(pw,salt)
	SV *pw;
	SV *salt; 

	INIT:
		char *cryptpw = NULL;
        	RETVAL = &PL_sv_undef;
	
	CODE:
		cryptpw = sha256_crypt( SvPVX(pw), SvPVX(salt) );
		if (cryptpw != NULL) {
			RETVAL = newSVpv(cryptpw,0);
		}

	OUTPUT:
		RETVAL

SV*
unix_sha512_crypt(pw,salt)
	SV *pw;
	SV *salt; 

	INIT:
		char *cryptpw = NULL;
        	RETVAL = &PL_sv_undef;
	
	CODE:
		cryptpw = sha512_crypt( SvPVX(pw), SvPVX(salt) );
		if (cryptpw != NULL) {
			RETVAL = newSVpv(cryptpw,0);
		}

	OUTPUT:
		RETVAL
