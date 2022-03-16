using System;
using System.Runtime.Serialization;

//	ExtendedCertificateInfo ::= SEQUENCE {
//		version		INTEGER,
//		certificate Certificate,
//		attributes	Attributes 
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS6
{
	[Serializable]
	public class ExtendedCertificateInfo : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer			>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<PKIX.Certificate	>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Attributes		    >().Factory(), Cast.N), 
		}; 
		// конструктор при сериализации
        protected ExtendedCertificateInfo(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public ExtendedCertificateInfo(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public ExtendedCertificateInfo(Integer version, PKIX.Certificate certificate, 
			Attributes attributes) : base(info, version, certificate, attributes) {}

		public Integer			Version		{ get { return (Integer			)this[0]; } } 
		public PKIX.Certificate	Certificate	{ get { return (PKIX.Certificate)this[1]; } }
		public Attributes		Attributes	{ get { return (Attributes		)this[2]; } }
	}
}
