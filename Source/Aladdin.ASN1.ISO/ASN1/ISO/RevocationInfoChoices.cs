using System;
using System.Runtime.Serialization;

// RevocationInfoChoices ::= SET OF RevocationInfoChoice

namespace Aladdin.ASN1.ISO
{
	[Serializable]
	public class RevocationInfoChoices : Set
	{
		// конструктор при сериализации
        protected RevocationInfoChoices(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public RevocationInfoChoices(IEncodable encodable) : 
			base(new ChoiceCreator<RevocationInfoChoice>().Factory(), encodable) {} 

		// конструктор при закодировании
		public RevocationInfoChoices(params Sequence[] values) : 
			base(new ChoiceCreator<RevocationInfoChoice>().Factory(), values) {} 
	}
}
