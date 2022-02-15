using System;

namespace Aladdin.ASN1.ISO.PKCS.PKCS12
{
	public static class OID
	{
		public const string pbe						= "1.2.840.113549.1.12.1"; 
		public const string pbe_sha1_rc4_128		= "1.2.840.113549.1.12.1.1";
		public const string pbe_sha1_rc4_40			= "1.2.840.113549.1.12.1.2";
		public const string pbe_sha1_tdes_192_cbc	= "1.2.840.113549.1.12.1.3";
		public const string pbe_sha1_tdes_128_cbc	= "1.2.840.113549.1.12.1.4";
		public const string pbe_sha1_rc2_128_cbc	= "1.2.840.113549.1.12.1.5";
		public const string pbe_sha1_rc2_40_cbc		= "1.2.840.113549.1.12.1.6";
		public const string bt						= "1.2.840.113549.1.12.10.1"; 
		public const string bt_key				    = "1.2.840.113549.1.12.10.1.1"; 
		public const string bt_shroudedKey		    = "1.2.840.113549.1.12.10.1.2"; 
		public const string bt_cert			        = "1.2.840.113549.1.12.10.1.3"; 
		public const string bt_crl				    = "1.2.840.113549.1.12.10.1.4"; 
		public const string bt_secret			    = "1.2.840.113549.1.12.10.1.5"; 
		public const string bt_safeContents	        = "1.2.840.113549.1.12.10.1.6"; 

	}
}
