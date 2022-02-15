using System;

// RevocationInfoChoices ::= SET OF RevocationInfoChoice

namespace Aladdin.ASN1.ISO
{
	public class RevocationInfoChoices : Set
	{
		// конструктор при раскодировании
		public RevocationInfoChoices(IEncodable encodable) : 
			base(new ChoiceCreator<RevocationInfoChoice>().Factory(), encodable) {} 

		// конструктор при закодировании
		public RevocationInfoChoices(params Sequence[] values) : 
			base(new ChoiceCreator<RevocationInfoChoice>().Factory(), values) {} 
	}
}
