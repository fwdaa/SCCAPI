using System;

// GeneralNames ::= SEQUENCE OF GeneralName

namespace Aladdin.ASN1.ISO.PKIX
{
	public class GeneralNames : Sequence
	{
		// конструктор при раскодировании
		public GeneralNames(IEncodable encodable) : 
			base(new ChoiceCreator<GeneralName>().Factory(), encodable) {}

		// конструктор при закодировании
		public GeneralNames(params IEncodable[] values) : 
			base(new ChoiceCreator<GeneralName>().Factory(), values) {}
	}
}
