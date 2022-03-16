using System;
using System.IO;
using System.Runtime.Serialization;

// PrintableAddress	::= SEQUENCE SIZE (1..ub-pds-physical-address-lines) OF PrintableString (SIZE (1..ub-pds-parameter-length))

//  ub-pds-parameter-length			INTEGER ::= 30
//	ub-pds-physical-address-lines	INTEGER ::= 6

namespace Aladdin.ASN1.ISO.PKIX.X400
{
	[Serializable]
	public class PrintableAddress : Sequence<PrintableString>
	{
		// конструктор при сериализации
        protected PrintableAddress(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public PrintableAddress(IEncodable encodable) : base(encodable) 
		{
			// проверить корректность
			if (Length <= 0 || Length > 6) throw new InvalidDataException(); 

			// для каждого элемента
			foreach (PrintableString obj in this) PrintableString.Validate(obj, false, 1, 30); 
		} 
		// конструктор при закодировании
		public PrintableAddress(params PrintableString[] values) : base(values) 
		{
			// проверить корректность
			if (Length <= 0 || Length > 6) throw new ArgumentException(); 

			// для каждого элемента
			foreach (PrintableString obj in this) PrintableString.Validate(obj, true, 1, 30); 
		} 
	}
}
