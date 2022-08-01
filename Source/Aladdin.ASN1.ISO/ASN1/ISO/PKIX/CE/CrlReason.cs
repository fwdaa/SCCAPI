namespace Aladdin.ASN1.ISO.PKIX.CE
{
	public enum CrlReason
	{
		Unspecified						=  0, 
		KeyCompromise					=  1,
		CACompromise					=  2,
		AffiliationChanged				=  3,
		Superseded						=  4,
		CessationOfOperation			=  5,
		CertificateHold					=  6,
		RemoveFromCRL					=  8,
		PrivilegeWithdrawn				=  9,
		AACompromise					= 10,
	}
}
