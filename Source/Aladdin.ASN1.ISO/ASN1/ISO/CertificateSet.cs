using System;
using System.Runtime.Serialization;

// CertificateSet ::= SET OF CertificateChoices

namespace Aladdin.ASN1.ISO
{
	[Serializable]
	public class CertificateSet : Set
	{
		// конструктор при сериализации
        protected CertificateSet(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public CertificateSet(IEncodable encodable) : 
			base(new ChoiceCreator<CertificateChoices>().Factory(), encodable) {} 

		// конструктор при закодировании
		public CertificateSet(params IEncodable[] values) : 
			base(new ChoiceCreator<CertificateChoices>().Factory(), values) {} 
	}
}
