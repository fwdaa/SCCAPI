using System;

namespace Aladdin.ASN1.ISO.OCSP
{
	public static class OID
	{
		public const string ocsp							= "1.3.6.1.5.5.7.48.1"; 
		public const string ocsp_basic						= "1.3.6.1.5.5.7.48.1.1"; 
		public const string ocsp_nonce						= "1.3.6.1.5.5.7.48.1.2";
		public const string ocsp_crl						= "1.3.6.1.5.5.7.48.1.3";
		public const string ocsp_response					= "1.3.6.1.5.5.7.48.1.4";
		public const string ocsp_nocheck					= "1.3.6.1.5.5.7.48.1.5";
		public const string ocsp_archive_cutoff				= "1.3.6.1.5.5.7.48.1.6";
		public const string ocsp_service_locator			= "1.3.6.1.5.5.7.48.1.7";
		public const string ocsp_pref_sig_algs				= "1.3.6.1.5.5.7.48.1.8";
		public const string ocsp_extended_revoke			= "1.3.6.1.5.5.7.48.1.9";
	}
}
