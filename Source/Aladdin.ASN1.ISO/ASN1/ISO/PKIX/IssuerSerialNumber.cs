using System;
using System.Runtime.Serialization;

//	IssuerSerialNumber ::= SEQUENCE {
//		issuer			Name,
//		serialNumber	INTEGER 
//	}

namespace Aladdin.ASN1.ISO.PKIX
{
	[Serializable]
	public class IssuerSerialNumber : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ChoiceCreator<Name	>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N), 
		}; 
		// конструктор при сериализации
        protected IssuerSerialNumber(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public IssuerSerialNumber(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public IssuerSerialNumber(IEncodable issuer, Integer serialNumber) : 
			base(info, issuer, serialNumber) {}

		public IEncodable	Issuer			{ get { return			 this[0]; } } 
		public Integer		SerialNumber	{ get { return (Integer	)this[1]; } }
	}
}
