using System;

namespace Aladdin.ASN1.GOST
{
	[Flags]
	public enum CryptoProPrivateKeyAttributes : long
	{
		None		= 0x0000,  
		Exportable	= 0x0001,  
		UserProtect	= 0x0002, 
		Exchange	= 0x0004,
		Ephemeral	= 0x0008,
		NonCachable	= 0x0010,
	}
}
