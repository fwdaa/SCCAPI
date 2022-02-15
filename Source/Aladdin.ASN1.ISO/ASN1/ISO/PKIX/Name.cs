using System;

// Name ::= CHOICE { rdnSequence RelativeDistinguishedNames }

namespace Aladdin.ASN1.ISO.PKIX
{
	public class Name : Choice
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<RelativeDistinguishedNames>().Factory(), Cast.N), 
		}; 
		// конструктор
		public Name() : base(info) {} 
	}
}
