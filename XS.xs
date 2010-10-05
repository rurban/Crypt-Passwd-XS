/*-
 * Copyright (c) 2010 cPanel, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "md5crypt.h"
#include "des.h"
#include "sha256crypt.h"
#include "sha512crypt.h"

MODULE = Crypt::Passwd::XS PACKAGE = Crypt::Passwd::XS

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
