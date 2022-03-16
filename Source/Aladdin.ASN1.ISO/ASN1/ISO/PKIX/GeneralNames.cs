using System;
using System.Runtime.Serialization;

// GeneralNames ::= SEQUENCE OF GeneralName

namespace Aladdin.ASN1.ISO.PKIX
{
	[Serializable]
	public class GeneralNames : Sequence
	{
		// конструктор при сериализации
        protected GeneralNames(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public GeneralNames(IEncodable encodable) : 
			base(new ChoiceCreator<GeneralName>().Factory(), encodable) {}

		// конструктор при закодировании
		public GeneralNames(params IEncodable[] values) : 
			base(new ChoiceCreator<GeneralName>().Factory(), values) {}
	}
}
