using System;

namespace Aladdin.ASN1.ISO.PKCS.PKCS9
{
	public static class OID
	{
		public const string emailAddress					= "1.2.840.113549.1.9.1";
		public const string unstructuredName				= "1.2.840.113549.1.9.2";
		public const string contentType						= "1.2.840.113549.1.9.3";
		public const string messageDigest					= "1.2.840.113549.1.9.4";
		public const string signingTime						= "1.2.840.113549.1.9.5";
		public const string countersignature				= "1.2.840.113549.1.9.6";
		public const string challengePassword				= "1.2.840.113549.1.9.7";
		public const string	unstructuredAddress				= "1.2.840.113549.1.9.8";
		public const string	extendedCertificateAttributes	= "1.2.840.113549.1.9.9";
		public const string	signingDescription				= "1.2.840.113549.1.9.13";
		public const string	extensionRequest				= "1.2.840.113549.1.9.14";
		public const string	smimeCapabilities				= "1.2.840.113549.1.9.15";
		public const string	smime							= "1.2.840.113549.1.9.16";
		public const string	smime_ct					    = "1.2.840.113549.1.9.16.1"; 
		public const string smime_ct_authData			    = "1.2.840.113549.1.9.16.1.2";
		public const string smime_ct_contentInfo			= "1.2.840.113549.1.9.16.1.6";
		public const string smime_ct_encKeyWithID		    = "1.2.840.113549.1.9.16.1.21";
		public const string smime_ct_authEnvelopedData	    = "1.2.840.113549.1.9.16.1.23";
		public const string	smime_algs			            = "1.2.840.113549.1.9.16.3";
		public const string	smime_esdh				        = "1.2.840.113549.1.9.16.3.5";
		public const string	smime_tdes192_wrap			    = "1.2.840.113549.1.9.16.3.6";
		public const string	smime_rc2_128_wrap			    = "1.2.840.113549.1.9.16.3.7";
		public const string	smime_pwri_kek			        = "1.2.840.113549.1.9.16.3.9";
		public const string	smime_ssdh		                = "1.2.840.113549.1.9.16.3.10";
		public const string	smime_esdh_hkdf_sha256          = "1.2.840.113549.1.9.16.3.19";
		public const string	smime_esdh_hkdf_sha384          = "1.2.840.113549.1.9.16.3.20";
		public const string	smime_esdh_hkdf_sha512          = "1.2.840.113549.1.9.16.3.21";
		public const string	smime_hkdf_sha256               = "1.2.840.113549.1.9.16.3.28";
		public const string	smime_hkdf_sha384               = "1.2.840.113549.1.9.16.3.29";
		public const string	smime_hkdf_sha512               = "1.2.840.113549.1.9.16.3.30";
		public const string	friendlyName					= "1.2.840.113549.1.9.20";
		public const string	localKeyId						= "1.2.840.113549.1.9.21";
		public const string	certTypes						= "1.2.840.113549.1.9.22";
		public const string certTypes_x509					= "1.2.840.113549.1.9.22.1"; 
		public const string certTypes_sdsi					= "1.2.840.113549.1.9.22.2";
		public const string	crlTypes						= "1.2.840.113549.1.9.23";
		public const string crlTypes_x509					= "1.2.840.113549.1.9.23.1"; 
		public const string	at								= "1.2.840.113549.1.9.25";
		public const string	at_pkcs15Token					= "1.2.840.113549.1.9.25.1";
		public const string	at_encryptedPrivateKeyInfo		= "1.2.840.113549.1.9.25.2";
		public const string	at_randomNonce					= "1.2.840.113549.1.9.25.3";
		public const string	at_sequenceNumber				= "1.2.840.113549.1.9.25.4";
		public const string	at_pkcs7PDU						= "1.2.840.113549.1.9.25.5";
	}
}
