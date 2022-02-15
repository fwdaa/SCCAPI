using System;

//	String ::= CHOICE {
//		ia5String		IA5String		(SIZE(1..pkcs-9-ub-pkcs9String)),
//		directoryString DirectoryString (SIZE(0..pkcs-9-ub-pkcs9String))
//	}
//	pkcs-9-ub-pkcs9String INTEGER ::= 255

namespace Aladdin.ASN1.ISO.PKCS
{
	public class String : Choice
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<IA5String			    >().Factory(1, 255), Cast.N), 
			new ObjectInfo(new ChoiceCreator<PKIX.DirectoryString	>().Factory(0, 255), Cast.N), 
		}; 
		// конструктор
		public String() : base(info) {} 
	}
}
