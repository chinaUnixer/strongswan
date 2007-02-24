/**
 * @file ca.c
 * 
 * @brief Implementation of ca_info_t.
 * 
 */

/*
 * Copyright (C) 2007 Andreas Steffen
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include "ca.h"

#include <library.h>
#include <debug.h>
#include <utils/linked_list.h>
#include <utils/identification.h>

typedef struct private_ca_info_t private_ca_info_t;

/**
 * Private data of a ca_info_t object.
 */
struct private_ca_info_t {
	/**
	 * Public interface for this ca info record
	 */
	ca_info_t public;
	
	/**
	 * Name of the ca info record
	 */
	char *name;

	/**
	 * Time when ca info record was installed
	 */
	time_t installed;

	/**
	 * Distinguished Name of the CA
	 */
	x509_t *cacert;
	
	/**
	 * List of crlDistributionPoints
	 */
	linked_list_t *crlURIs;

	/**
	 * List of ocspAccessPoints
	 */
	linked_list_t *ocspURIs;
};

/**
 * Implements ca_info_t.add_crluri
 */
static void add_crluri(private_ca_info_t *this, const char* uri)
{
	if (uri == NULL)
	{
		return;
	}
	if (strncasecmp(uri, "http", 4) != 0
    &&  strncasecmp(uri, "ldap", 4) != 0
    &&  strncasecmp(uri, "file", 4) != 0 
	&&  strncasecmp(uri, "ftp",  3) != 0)
	{
		DBG1("  invalid crl uri '%s'", uri);
		return;
	}
}

/**
 * Implements ca_info_t.add_ocspuri
 */
static void add_ocspuri(private_ca_info_t *this, const char* uri)
{
	if (uri == NULL)
	{
		return;
	}
	if (strncasecmp(uri, "http", 4) != 0)
	{
		DBG1("  invalid ocsp uri '%s'", uri);
		return;
	}
}

/**
 * Implements ca_info_t.destroy
 */
static void destroy(private_ca_info_t *this)
{
	this->crlURIs->destroy_offset(this->crlURIs,
								  offsetof(identification_t, destroy));
	this->ocspURIs->destroy_offset(this->ocspURIs,
								   offsetof(identification_t, destroy));
	free(this->name);
	free(this);
}

/**
 * output handler in printf()
 */
static int print(FILE *stream, const struct printf_info *info,
				 const void *const *args)
{
	private_ca_info_t *this = *((private_ca_info_t**)(args[0]));
	bool utc = TRUE;
	int written = 0;
	x509_t *cacert;
	chunk_t keyid;
	
	if (info->alt)
	{
		utc = *((bool*)args[1]);
	}
	
	if (this == NULL)
	{
		return fprintf(stream, "(null)");
	}
	
	written += fprintf(stream, "%#T, \"%s\"\n", &this->installed, utc, this->name);

	cacert = this->cacert;
	written += fprintf(stream, "    authname:  '%D'\n", cacert->get_subject(cacert));

	keyid = cacert->get_keyid(cacert);
	written += fprintf(stream, "    keyid:      %#B\n", &keyid);

	return written;
}

/**
 * register printf() handlers
 */
static void __attribute__ ((constructor))print_register()
{
	register_printf_function(PRINTF_CAINFO, print, arginfo_ptr_alt_ptr_int);
}

/*
 * Described in header.
 */
ca_info_t *ca_info_create(const char *name, const x509_t *cacert)
{
	private_ca_info_t *this = malloc_thing(private_ca_info_t);
	
	/* initialize */
	this->installed = time(NULL);
	this->name = strdup(name);
	this->cacert = cacert;
	this->crlURIs = linked_list_create();
	this->ocspURIs = linked_list_create();
	
	/* public functions */
	this->public.add_crluri = (void (*) (ca_info_t*,const char*))add_crluri;
	this->public.add_ocspuri = (void (*) (ca_info_t*,const char*))add_ocspuri;
	this->public.destroy = (void (*) (ca_info_t*))destroy;

	return &this->public;
}
