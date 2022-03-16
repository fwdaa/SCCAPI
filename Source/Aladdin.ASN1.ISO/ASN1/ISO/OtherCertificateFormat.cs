using System;
using System.Runtime.Serialization;

//	OtherCertificateFormat ::= SEQUENCE {
//		otherCertFormat OBJECT IDENTIFIER,
//		otherCert ANY DEFINED BY otherCertFormat 
//	}

namespace Aladdin.ASN1.ISO
{
	[Serializable]
	public class OtherCertificateFormat : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N), 
			new ObjectInfo(    ImplicitCreator				    .Factory  , Cast.N), 
		}; 
		// конструктор при сериализации
        protected OtherCertificateFormat(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public OtherCertificateFormat(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public OtherCertificateFormat(ObjectIdentifier otherCertFormat, IEncodable otherCert) : 
			base(info, otherCertFormat, otherCert) {}

		public ObjectIdentifier	OtherCertFormat	{ get { return (ObjectIdentifier)this[0]; } } 
		public IEncodable		OtherCert		{ get { return                   this[1]; } }
	}
}
