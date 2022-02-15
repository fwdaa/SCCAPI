using System; 

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	[Flags]
	public enum ReasonFlags : long
	{
		Unused						= 0x0001, 
		KeyCompromise				= 0x0002, 
		CACompromise				= 0x0004, 
		AffiliationChanged			= 0x0008, 
		Superseded					= 0x0010, 
		CessationOfOperation		= 0x0020, 
		CertificateHold				= 0x0040,
		PrivilegeWithdrawn			= 0x0080,
		AACompromise				= 0x0100,
	}
}
