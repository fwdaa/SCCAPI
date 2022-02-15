using System;

//	PostalCode ::= CHOICE {
//		numeric-code   NumericString   (SIZE (1..ub-postal-code-length)),
//		printable-code PrintableString (SIZE (1..ub-postal-code-length)) 
//	}
//	ub-postal-code-length INTEGER ::= 16

namespace Aladdin.ASN1.ISO.PKIX.X400
{
	public class PostalCode : Choice
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<NumericString  >().Factory(1, 16), Cast.N), 
			new ObjectInfo(new ObjectCreator<PrintableString>().Factory(1, 16), Cast.N), 
		}; 
		// конструктор
		public PostalCode() : base(info) {} 
	}
}
