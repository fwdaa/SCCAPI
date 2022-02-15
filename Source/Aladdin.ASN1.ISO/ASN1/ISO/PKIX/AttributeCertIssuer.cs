using System;

//	AttributeCertIssuer ::= CHOICE {
//		v1Form					GeneralNames,
//		v2Form   [0] IMPLICIT	AttrributeGeneralNames 
// }

namespace Aladdin.ASN1.ISO.PKIX
{
	public class AttributeCertIssuer : Choice
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<GeneralNames			>().Factory(), Cast.N, Tag.Any		), 
			new ObjectInfo(new ObjectCreator<AttrributeGeneralNames >().Factory(), Cast.N, Tag.Context(0)), 
		}; 
		// конструктор
		public AttributeCertIssuer() : base(info) {} 
	}
}
