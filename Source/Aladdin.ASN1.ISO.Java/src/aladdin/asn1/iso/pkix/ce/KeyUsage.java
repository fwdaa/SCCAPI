package aladdin.asn1.iso.pkix.ce;

public final class KeyUsage 
{
	public static final long NONE					= 0x0000;  
	public static final long DIGITAL_SIGNATURE		= 0x0001;  
	public static final long NON_REPUDIATION		= 0x0002; 
	public static final long KEY_ENCIPHERMENT		= 0x0004;
	public static final long DATA_ENCIPHERMENT		= 0x0008;
	public static final long KEY_AGREEMENT			= 0x0010;
	public static final long CERTIFICATE_SIGNATURE	= 0x0020;
	public static final long CRL_SIGNATURE			= 0x0040;
	public static final long ENCIPHER_ONLY			= 0x0080;
	public static final long DECIPHER_ONLY			= 0x0100;  
}
