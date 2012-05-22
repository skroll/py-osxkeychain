/*
 * Copyright (c) 2012, Scott Kroll
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met: 
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * The views and conclusions contained in the software and documentation are
 * those of the authors and should not be interpreted as representing official
 * policies, either expressed or implied, of the original authors.
 */ 

#include <Python.h>
#include <Security/Security.h>
#include <sys/param.h>

/* constants ------------------------------------------------------------{{{ */

static struct int_constant {
	char *name;
	long  value;
} keychain_constants[] = {
	/* security domain types */
	{"DOMAIN_USER",   kSecPreferencesDomainUser},
	{"DOMAIN_SYSTEM", kSecPreferencesDomainSystem},
	{"DOMAIN_COMMON", kSecPreferencesDomainCommon},

	/* security protocol types */
	{"PROTOCOL_TYPE_FTP",         kSecProtocolTypeFTP},
	{"PROTOCOL_TYPE_FTP_ACCOUNT", kSecProtocolTypeFTPAccount},
	{"PROTOCOL_TYPE_HTTP",        kSecProtocolTypeHTTP},
	{"PROTOCOL_TYPE_IRC",         kSecProtocolTypeIRC},
	{"PROTOCOL_TYPE_NNTP",        kSecProtocolTypeNNTP},
	{"PROTOCOL_TYPE_POP3",        kSecProtocolTypePOP3},
	{"PROTOCOL_TYPE_SMTP",        kSecProtocolTypeSMTP},
	{"PROTOCOL_TYPE_SOCKS",       kSecProtocolTypeSOCKS},
	{"PROTOCOL_TYPE_IMAP",        kSecProtocolTypeIMAP},
	{"PROTOCOL_TYPE_LDAP",        kSecProtocolTypeLDAP},
	{"PROTOCOL_TYPE_APPLETALK",   kSecProtocolTypeAppleTalk},
	{"PROTOCOL_TYPE_AFP",         kSecProtocolTypeAFP},
	{"PROTOCOL_TYPE_TELNET",      kSecProtocolTypeTelnet},
	{"PROTOCOL_TYPE_SSH",         kSecProtocolTypeSSH},
	{"PROTOCOL_TYPE_FTPS",        kSecProtocolTypeFTPS},
	{"PROTOCOL_TYPE_HTTPS",       kSecProtocolTypeHTTPS},
	{"PROTOCOL_TYPE_HTTP_PROXY",  kSecProtocolTypeHTTPProxy},
	{"PROTOCOL_TYPE_HTTPS_PROXY", kSecProtocolTypeHTTPSProxy},
	{"PROTOCOL_TYPE_FTP_PROXY",   kSecProtocolTypeFTPProxy},
	{"PROTOCOL_TYPE_CIFS",        kSecProtocolTypeCIFS},
	{"PROTOCOL_TYPE_SMB",         kSecProtocolTypeSMB},
	{"PROTOCOL_TYPE_RTSP",        kSecProtocolTypeRTSP},
	{"PROTOCOL_TYPE_RTSP_PROXY",  kSecProtocolTypeRTSPProxy},
	{"PROTOCOL_TYPE_DAAP",        kSecProtocolTypeDAAP},
	{"PROTOCOL_TYPE_DPPC",        kSecProtocolTypeEPPC},
	{"PROTOCOL_TYPE_IPP",         kSecProtocolTypeIPP},
	{"PROTOCOL_TYPE_NNTPS",       kSecProtocolTypeNNTPS},
	{"PROTOCOL_TYPE_LDAPS",       kSecProtocolTypeLDAPS},
	{"PROTOCOL_TYPE_TELNETS",     kSecProtocolTypeTelnetS},
	{"PROTOCOL_TYPE_IMAPS",       kSecProtocolTypeIMAPS},
	{"PROTOCOL_TYPE_IRCS",        kSecProtocolTypeIRCS},
	{"PROTOCOL_TYPE_POP3S",       kSecProtocolTypePOP3S},
	{"PROTOCOL_TYPE_CVSPSERVER",  kSecProtocolTypeCVSpserver},
	{"PROTOCOL_TYPE_SVN",         kSecProtocolTypeSVN},
	{"PROTOCOL_TYPE_ANY",         kSecProtocolTypeAny},

	/* security authentication types */
	{"AUTHENTICATION_TYPE_NTLM",        kSecAuthenticationTypeNTLM},
	{"AUTHENTICATION_TYPE_MSN",         kSecAuthenticationTypeMSN},
	{"AUTHENTICATION_TYPE_DPA",         kSecAuthenticationTypeDPA},
	{"AUTHENTICATION_TYPE_RPA",         kSecAuthenticationTypeRPA},
	{"AUTHENTICATION_TYPE_HTTP_BASIC",  kSecAuthenticationTypeHTTPBasic},
	{"AUTHENTICATION_TYPE_HTTP_DIGEST", kSecAuthenticationTypeHTTPDigest},
	{"AUTHENTICATION_TYPE_HTML_FORM",   kSecAuthenticationTypeHTMLForm},
	{"AUTHENTICATION_TYPE_DEFAULT",     kSecAuthenticationTypeDefault},
	{"AUTHENTICATION_TYPE_ANY",         kSecAuthenticationTypeAny},

	{NULL, NULL} /* sentinel */
};

/* }}} */

/* exceptions -----------------------------------------------------------{{{ */

static PyObject *KC_BaseError = NULL;
static PyObject *KC_UnimplementedError = NULL;

/* }}} */
/* capsule wrappers -----------------------------------------------------{{{ */

#define SecKeychainRef_Name "SecKeychainRef"

static PyObject *
SecKeychainRef_Capsule_GetPointer( PyObject *capsule )
{
	return PyCapsule_GetPointer( capsule, SecKeychainRef_Name );
}

static void
SecKeychainRef_Capsule_Destructor( PyObject *capsule )
{
	SecKeychainRef  keychainref = SecKeychainRef_Capsule_GetPointer( capsule );

	if ( keychainref ) {
		CFRelease( keychainref );
	}
}

static PyObject *
SecKeychainRef_Capsule_New( SecKeychainRef  keychainref )
{
	CFRetain( keychainref );

	return PyCapsule_New( keychainref, SecKeychainRef_Name,
	                      SecKeychainRef_Capsule_Destructor );
}

/* }}} */
/* methods --------------------------------------------------------------{{{ */
static PyObject *
get_search_list( PyObject *self,
                 PyObject *args )
{
	PyObject   *list;
	CFArrayRef  search_list;
	OSStatus    status;
	CFIndex     count;
	int         i;
	int         domain = -1;

	if ( !PyArg_ParseTuple( args, "|i", &domain ) ) {
		return NULL;
	}

	if ( domain >= 0 ) {
		status = SecKeychainCopyDomainSearchList( domain, &search_list );
	}
	else {
		status = SecKeychainCopySearchList( &search_list );
	}

	if ( status ) {
		/* TODO: Error */
		CFRelease( search_list );
		return NULL;
	}

	count = CFArrayGetCount( search_list );

	list = PyList_New( (Py_ssize_t)count );

	if ( !list ) {
		/* TODO: Error */
		CFRelease( search_list );
		return NULL;
	}

	for ( i = 0; i < count; i++ ) {
		PyObject       *keychain;
		SecKeychainRef  keychainref;

		keychainref = CFArrayGetValueAtIndex( search_list, i );

		/* Get ownership of keychain reference */
		keychain = SecKeychainRef_Capsule_New( keychainref );

		if ( !keychain ) {
			/* TODO: Error */
			CFRelease( keychainref );
			CFRelease( search_list );
			return NULL;
		}

		if ( PyList_SetItem( list, i, keychain ) ) {
			/* TODO: Error */
			CFRelease( keychainref );
			CFRelease( search_list );
			return NULL;
		}
	}

	CFRelease( search_list );

	return (PyObject *)list;
}

static PyObject *
get_path( PyObject *self,
          PyObject *args )
{
	char            path[MAXPATHLEN + 1];
	UInt32          path_len = MAXPATHLEN + 1;
	OSStatus        status;
	PyObject       *keychain_capsule;
	SecKeychainRef  keychainref;

	if ( !PyArg_ParseTuple( args, "O", &keychain_capsule ) ) {
		return NULL;
	}

	keychainref = SecKeychainRef_Capsule_GetPointer( keychain_capsule );

	if ( !keychainref ) {
		/* TODO: Error */
		return NULL;
	}

	status = SecKeychainGetPath( keychainref, &path_len, path );

	if ( status ) {
		/* TODO: Error */
		return NULL;
	}

	return PyString_FromStringAndSize( path, path_len );
}

static PyObject *
find_internet_password( CFTypeRef              keychain_or_array,
                        PyObject              *server_name,
                        PyObject              *account_name,
                        PyObject              *security_domain,
                        PyObject              *path,
                        UInt16                 port,
                        SecProtocolType        protocol,
                        SecAuthenticationType  authentication_type )
{
	UInt32    server_name_len     = 0;
	UInt32    account_name_len    = 0;
	UInt32    security_domain_len = 0;
	UInt32    path_len            = 0;
	UInt32    password_len        = 0;
	char     *server_name_s       = NULL;
	char     *account_name_s      = NULL;
	char     *security_domain_s   = NULL;
	char     *path_s              = NULL;
	char     *password_s          = NULL;
	OSStatus  status;

	if ( server_name ) {
		if ( !PyObject_TypeCheck( server_name, &PyString_Type ) ) {
			PyErr_SetString( PyExc_TypeError, "server_name must be a string" );
			return NULL;
		}

		server_name_len = PyString_Size( server_name );
		server_name_s   = PyString_AsString( server_name );
	}

	if ( account_name ) {
		account_name_len = PyString_Size( account_name );
		account_name_s   = PyString_AsString( account_name );
	}

	if ( security_domain ) {
		security_domain_len = PyString_Size( security_domain );
		security_domain_s   = PyString_AsString( security_domain );
	}

	if ( path ) {
		path_len = PyString_Size( path );
		path_s   = PyString_AsString( path );
	}

	status = SecKeychainFindInternetPassword( keychain_or_array, server_name_len,
	                                          server_name_s, security_domain_len,
	                                          security_domain_s, account_name_len,
	                                          account_name_s, path_len, path_s,
	                                          port, protocol, authentication_type,
	                                          &password_len, &password_s, NULL );

	if ( status == 0 ) {
		return PyString_FromStringAndSize( password_s, password_len );
	}
	else {
		Py_INCREF( Py_None );
		return Py_None;
	}
}

/*
 * ===  FUNCTION  =============================================================
 *         Name:  py_find_internet_password
 *  Description:  
 * ============================================================================
 */
static PyObject *
py_find_internet_password( PyObject     *self, 
                           PyObject     *args,
                           PyObject     *kwds )
{
	PyObject              *keychains           = NULL;
	PyObject              *server_name         = NULL;
	PyObject              *account_name        = NULL;
	PyObject              *security_domain     = NULL;
	PyObject              *path                = NULL;
	PyObject              *password            = NULL;
	UInt16                 port                = 0;
	SecProtocolType        protocol_type       = kSecProtocolTypeAny;
	SecAuthenticationType  authentication_type = kSecAuthenticationTypeDefault;

	static char *kwlist[] = {"server_name", "account_name", "keychains",
		"security_domain", "path", "port", "protocol_type",
		"authentication_type", NULL};

	if ( !PyArg_ParseTupleAndKeywords( args, kwds, "OO|OOOiii", kwlist,
	                                   &server_name, &account_name,
	                                   &keychains, &protocol_type, &path,
	                                   &port, &authentication_type ) ) {
		return NULL;
	}

	if ( keychains ) {
		if ( PyObject_TypeCheck( keychains, &PyList_Type ) ) {
			CFMutableArrayRef  array = NULL;
			Py_ssize_t         i;
			Py_ssize_t         list_len = PyList_Size( keychains );

			array = CFArrayCreateMutable( NULL, list_len, NULL );

			for ( i = 0; i < list_len; i++ ) {
				PyObject       *keychain_capsule = PyList_GetItem( keychains, i );
				SecKeychainRef  keychainref = SecKeychainRef_Capsule_GetPointer( keychain_capsule );

				if ( !keychainref ) {
					/* TODO: Error */
					continue;
				}

				CFArrayAppendValue( array, keychainref );
			}

			password = find_internet_password( array, server_name, account_name,
	                                           security_domain, path, port, protocol_type,
	                                           authentication_type );

			if ( array ) {
				CFRelease( array );
			}
		}
		else if ( PyObject_TypeCheck( keychains, &PyCapsule_Type ) ) {
			SecKeychainRef  keychainref = SecKeychainRef_Capsule_GetPointer( keychains );

			password = find_internet_password( keychainref, server_name, account_name,
			                                   security_domain, path, port,
			                                   protocol_type, authentication_type );
		}
		else {
			PyErr_SetString( PyExc_TypeError, "keychains is invalid type" );

			password = NULL;
		}
	}
	else {
		password = find_internet_password( NULL, server_name, account_name,
		                                   security_domain, path, port,
		                                   protocol_type, authentication_type );
	}

	return password;
}


/* }}} */
/* module initialization ------------------------------------------------{{{ */

static PyMethodDef
methods[] = {
	{"get_search_list", (PyCFunction)get_search_list, METH_VARARGS,
		"Get search list of keychains" },
	{"get_path", (PyCFunction)get_path, METH_VARARGS,
		"Get path of keychain" },
	{"find_internet_password", (PyCFunction)py_find_internet_password,
		METH_VARARGS, "Get an internet password" },
	{NULL} /* sentinel */
};

#if PY_MAJOR_VERSION >= 3

static struct PyModuleDef
osxkeychain_module = {
	PyModuleDef_HEAD_INIT,
	"_osxmodule",
	NULL,
	-1,
	methods
};

#define RETURN_MODULE_ERROR return NULL
#define RETURN_MODULE( _m ) return _m

#else /* PY_MAJOR_VERSION < 3 */

#define RETURN_MODULE_ERROR return
#define RETURN_MODULE( _m )

#endif /* PY_MAJOR_VERSION < 3 */

PyMODINIT_FUNC
#if PY_MAJOR_VERSION >= 3
PyInit_osxkeychain( void )
#else /* PY_MAJOR_VERSION < 3 */
init_osxkeychain( void )
#endif /* PY_MAJOR_VERSION < 3 */
{
	PyObject *m;

#if PY_MAJOR_VERSION >= 3
	m = PyModule_Create( &osxkeychain_module );
#else /* PY_MAJOR_VERSION < 3 */
	m = Py_InitModule3( "_osxkeychain", methods, "Mac OS X Keychain Library" );
#endif /* PY_MAJOR_VERSION < 3 */

	if ( m == NULL ) {
		RETURN_MODULE_ERROR;
	}

	/* constants */
	{
		struct int_constant *constant = keychain_constants;

		while ( constant->name ) {
			if ( PyModule_AddIntConstant( m, constant->name, constant->value ) ) {
				return -1;
			}

			++constant;
		}
	}

	/* exceptions */
	{
		/* BaseError */
		KC_BaseError = PyErr_NewException( "osxkeychain.BaseError", NULL, NULL );
		Py_INCREF( KC_BaseError );
		PyModule_AddObject( m, "BaseError", KC_BaseError );

		/* UnimplementedError */
		KC_UnimplementedError = PyErr_NewException( "osxkeychain.UnimplementedError", KC_BaseError, NULL );
		Py_INCREF( KC_UnimplementedError );
		PyModule_AddObject( m, "UnimplementedError", KC_UnimplementedError );
	}

	RETURN_MODULE( m );
}

/* }}} */

