using System;

//	BuiltInDomainDefinedAttribute ::= SEQUENCE {
//		type  PrintableString (SIZE (1..ub-domain-defined-attribute-type-length)),
//		value PrintableString (SIZE (1..ub-domain-defined-attribute-value-length)) 
//	}
//	ub-domain-defined-attribute-type-length  INTEGER ::= 8
//	ub-domain-defined-attribute-value-length INTEGER ::= 128

namespace Aladdin.ASN1.ISO.PKIX.X400
{
	public class BuiltInDomainDefinedAttribute : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<PrintableString>().Factory(1,   8), Cast.N), 
			new ObjectInfo(new ObjectCreator<PrintableString>().Factory(1, 128), Cast.N), 
		}; 
		// конструктор при раскодировании
		public BuiltInDomainDefinedAttribute(IEncodable encodable) : base(encodable, info) {} 

		// конструктор при закодировании
		public BuiltInDomainDefinedAttribute(PrintableString type, PrintableString value) : 
			base(info, type, value) {}

		public PrintableString Type	 { get { return (PrintableString)this[0]; } }
		public PrintableString Value { get { return (PrintableString)this[1]; } }
	}
}
