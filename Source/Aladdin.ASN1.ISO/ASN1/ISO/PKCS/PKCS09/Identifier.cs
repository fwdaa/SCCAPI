using System;

//	Identifier ::= CHOICE {
//		string             UTF8String,
//		generalName        GeneralName
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS9
{
	public class Identifier : Choice
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<UTF8String		    >().Factory(), Cast.N), 
			new ObjectInfo(new ChoiceCreator<PKIX.GeneralName	>().Factory(), Cast.N), 
		}; 
		// конструктор
		public Identifier() : base(info) {} 
	}
}
