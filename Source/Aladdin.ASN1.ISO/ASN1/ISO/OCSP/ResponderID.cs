
// 	ResponderID ::= CHOICE {
// 		byName   [1] EXPLICIT Name,
// 		byKey    [2] EXPLICIT OCTET STRING
// 	}

namespace Aladdin.ASN1.ISO.OCSP
{
	public class ResponderID : Choice
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ChoiceCreator<PKIX.Name  >().Factory(), Cast.E, Tag.Context(0)), 
			new ObjectInfo(new ObjectCreator<OctetString>().Factory(), Cast.E, Tag.Context(1)) 
		}; 
		// конструктор
		public ResponderID() : base(info) {} 
	}
}
