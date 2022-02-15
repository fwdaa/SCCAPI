using System;

//	TeletexPersonalName ::= SET {
//		surname				 [0] IMPLICIT TeletexString (SIZE (1..ub-surname-length)),
//		given-name			 [1] IMPLICIT TeletexString (SIZE (1..ub-given-name-length))			OPTIONAL,
//		initials			 [2] IMPLICIT TeletexString (SIZE (1..ub-initials-length))				OPTIONAL,
//		generation-qualifier [3] IMPLICIT TeletexString (SIZE (1..ub-generation-qualifier-length))	OPTIONAL 
//	}
//	ub-surname-length				INTEGER ::= 40
//	ub-given-name-length			INTEGER ::= 16
//	ub-initials-length				INTEGER ::= 5
//	ub-generation-qualifier-length	INTEGER ::= 3

namespace Aladdin.ASN1.ISO.PKIX.X400
{
	public class TeletexPersonalName : Set
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<TeletexString>().Factory(1, 40), Cast.N, Tag.Context(0)), 
			new ObjectInfo(new ObjectCreator<TeletexString>().Factory(1, 16), Cast.O, Tag.Context(1)), 
			new ObjectInfo(new ObjectCreator<TeletexString>().Factory(1,  5), Cast.O, Tag.Context(2)), 
			new ObjectInfo(new ObjectCreator<TeletexString>().Factory(1,  3), Cast.O, Tag.Context(3)), 
		}; 
		// конструктор при раскодировании
		public TeletexPersonalName(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public TeletexPersonalName(TeletexString surname, TeletexString givenName,
			TeletexString initials, TeletexString generationQualifier) : 
			base(info, surname, givenName, initials, generationQualifier) {}

		public TeletexString Surname			 { get { return (TeletexString)this[0];	} }
		public TeletexString GivenName			 { get { return (TeletexString)this[1];	} }
		public TeletexString Initials			 { get { return (TeletexString)this[2];	} }
		public TeletexString GenerationQualifier { get { return (TeletexString)this[3]; } }
	}
}
