using System;

//	TeletexDomainDefinedAttribute ::= SEQUENCE {
//		type  TeletexString (SIZE (1..ub-domain-defined-attribute-type-length)),
//		value TeletexString (SIZE (1..ub-domain-defined-attribute-value-length)) 
//	}
//	ub-domain-defined-attribute-type-length  INTEGER ::= 8
//	ub-domain-defined-attribute-value-length INTEGER ::= 128

namespace Aladdin.ASN1.ISO.PKIX.X400
{
	public class TeletexDomainDefinedAttribute : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<TeletexString>().Factory(1,   8), Cast.N, Tag.Any), 
			new ObjectInfo(new ObjectCreator<TeletexString>().Factory(1, 128), Cast.N, Tag.Any), 
		}; 
		// конструктор при раскодировании
		public TeletexDomainDefinedAttribute(IEncodable encodable) : base(encodable, info) {} 

		// конструктор при закодировании
		public TeletexDomainDefinedAttribute(TeletexString type, TeletexString value) : 
			base(info, type, value) {}

		public TeletexString Type	{ get { return (TeletexString)this[0]; } }
		public TeletexString Value	{ get { return (TeletexString)this[1]; } }
	}
}
