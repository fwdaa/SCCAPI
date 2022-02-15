using System;

//	PrivateDomainName ::= CHOICE {
//		numeric   NumericString   (SIZE (1..ub-domain-name-length)),
//		printable PrintableString (SIZE (1..ub-domain-name-length)) 
//	}
//	ub-domain-name-length INTEGER ::= 16

namespace Aladdin.ASN1.ISO.PKIX.X400
{
	public class PrivateDomainName : Choice
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<NumericString  >().Factory(1, 16), Cast.N), 
			new ObjectInfo(new ObjectCreator<PrintableString>().Factory(1, 16), Cast.N), 
		}; 
		// конструктор
		public PrivateDomainName() : base(info) {} 
	}
}
