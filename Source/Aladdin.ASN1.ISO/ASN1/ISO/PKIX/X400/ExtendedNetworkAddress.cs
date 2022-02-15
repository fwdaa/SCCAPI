using System;

//	ExtendedNetworkAddress ::= CHOICE {
//		e163-4-address				E163-4-address,
//		psap-address   [0] IMPLICIT PresentationAddress 
//	}

namespace Aladdin.ASN1.ISO.PKIX.X400
{
	public class ExtendedNetworkAddress : Choice
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<E1634Address       >().Factory(), Cast.N, Tag.Context(0)), 
			new ObjectInfo(new ObjectCreator<PresentationAddress>().Factory(), Cast.O, Tag.Context(1)), 
		}; 
		// конструктор 
		public ExtendedNetworkAddress() : base(info) {} 
	}
}
