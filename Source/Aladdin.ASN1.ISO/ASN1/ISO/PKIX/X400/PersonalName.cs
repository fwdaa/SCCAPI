using System;
using System.Runtime.Serialization;

//	PersonalName ::= SET {
//		surname				 [0] IMPLICIT PrintableString (SIZE (1..ub-surname-length)),
//		given-name			 [1] IMPLICIT PrintableString (SIZE (1..ub-given-name-length))			 OPTIONAL,
//		initials			 [2] IMPLICIT PrintableString (SIZE (1..ub-initials-length))			 OPTIONAL,
//		generation-qualifier [3] IMPLICIT PrintableString (SIZE (1..ub-generation-qualifier-length)) OPTIONAL 
//	}
//	ub-surname-length				INTEGER ::= 40
//	ub-given-name-length			INTEGER ::= 16
//	ub-initials-length				INTEGER ::= 5
//	ub-generation-qualifier-length	INTEGER ::= 3

namespace Aladdin.ASN1.ISO.PKIX.X400
{
	[Serializable]
	public class PersonalName : Set
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<PrintableString>().Factory(1, 40), Cast.N, Tag.Context(0)), 
			new ObjectInfo(new ObjectCreator<PrintableString>().Factory(1, 16), Cast.O, Tag.Context(1)), 
			new ObjectInfo(new ObjectCreator<PrintableString>().Factory(1,  5), Cast.O, Tag.Context(2)), 
			new ObjectInfo(new ObjectCreator<PrintableString>().Factory(1,  3), Cast.O, Tag.Context(3)), 
		}; 
		// конструктор при сериализации
        protected PersonalName(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public PersonalName(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public PersonalName(PrintableString surname, PrintableString givenName,
			PrintableString initials, PrintableString generationQualifier) : 
			base(info, surname, givenName, initials, generationQualifier) {}

		public PrintableString Surname				{ get { return (PrintableString)this[0]; } }
		public PrintableString GivenName			{ get { return (PrintableString)this[1]; } }
		public PrintableString Initials				{ get { return (PrintableString)this[2]; } }
		public PrintableString GenerationQualifier	{ get { return (PrintableString)this[3]; } }
	}
}
