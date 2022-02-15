using System; 

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	[Flags]
	public enum KeyUsage : long
	{
		None						= 0x0000,  
		DigitalSignature			= 0x0001,  
		NonRepudiation				= 0x0002, 
		KeyEncipherment				= 0x0004,
		DataEncipherment			= 0x0008,
		KeyAgreement				= 0x0010,
		KeyExchange					= 0x0014,
		CertificateSignature		= 0x0020,
		CrlSignature				= 0x0040,
		DataSignature				= 0x0061,  
		EncipherOnly				= 0x0080,
		DecipherOnly				= 0x0100 
	}
}


