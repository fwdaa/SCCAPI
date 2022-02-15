package aladdin.asn1.iso.pkix.ce;

public final class ReasonFlags 
{
	public static final int UNUSED					= 0x0001;  
	public static final int KEY_COMPROMISE			= 0x0002; 
	public static final int CA_COMPROMISE			= 0x0004; 
	public static final int AFFILIATION_CHANGED		= 0x0008; 
	public static final int SUPERSEDED				= 0x0010; 
	public static final int CESSATION_OF_OPERATION	= 0x0020; 
	public static final int CERTIFICATE_HOLD		= 0x0040;
	public static final int PRIVILEGE_WITHDRAWN		= 0x0080;
	public static final int AA_COMPROMISE			= 0x0100;
}
