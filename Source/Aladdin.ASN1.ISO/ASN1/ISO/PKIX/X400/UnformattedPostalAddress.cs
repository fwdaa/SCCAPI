using System;
using System.Runtime.Serialization;

//	UnformattedPostalAddress ::= SET {
//		printable-address	PrintableAddress OPTIONAL,
//		teletex-string		TeletexString (SIZE (1..ub-unformatted-address-length)) OPTIONAL 
//	}
//	ub-unformatted-address-length	INTEGER ::= 180

namespace Aladdin.ASN1.ISO.PKIX.X400
{
	[Serializable]
	public class UnformattedPostalAddress : Set
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<PrintableAddress>().Factory(      ), Cast.O), 
			new ObjectInfo(new ObjectCreator<TeletexString   >().Factory(1, 180), Cast.O), 
		}; 
		// конструктор при сериализации
        protected UnformattedPostalAddress(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public UnformattedPostalAddress(IEncodable encodable) : base(encodable, info) {} 

		// конструктор при закодировании
		public UnformattedPostalAddress(PrintableAddress printableAddress, TeletexString teletexString) :
			base(info, printableAddress, teletexString) {}

		public PrintableAddress PrintableAddress	{ get { return (PrintableAddress)this[0]; } }
		public TeletexString	TeletexString		{ get { return (TeletexString	)this[1]; } }
	}
}
