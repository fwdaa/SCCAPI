using System;

// CertificateSet ::= SET OF CertificateChoices

namespace Aladdin.ASN1.ISO
{
	public class CertificateSet : Set
	{
		// конструктор при раскодировании
		public CertificateSet(IEncodable encodable) : 
			base(new ChoiceCreator<CertificateChoices>().Factory(), encodable) {} 

		// конструктор при закодировании
		public CertificateSet(params IEncodable[] values) : 
			base(new ChoiceCreator<CertificateChoices>().Factory(), values) {} 
	}
}
