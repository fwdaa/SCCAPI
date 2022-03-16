using System;
using System.Runtime.Serialization;

//	PDSParameter ::= SET {
//		printable-string PrintableString (SIZE(1..ub-pds-parameter-length)) OPTIONAL,
//		teletex-string	 TeletexString	 (SIZE(1..ub-pds-parameter-length)) OPTIONAL 
//	}
//  ub-pds-parameter-length INTEGER ::= 30

namespace Aladdin.ASN1.ISO.PKIX.X400
{
	[Serializable]
	public class PDSParameter : Set
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<PrintableString>().Factory(1, 30), Cast.O), 
			new ObjectInfo(new ObjectCreator<TeletexString  >().Factory(1, 30), Cast.O), 
		}; 
		// конструктор при сериализации
        protected PDSParameter(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public PDSParameter(IEncodable encodable) : base(encodable, info) {}  

		// конструктор при закодировании
		public PDSParameter(PrintableString printableString, TeletexString teletexString) : 
			base(info, printableString, teletexString) {}

		public PrintableString PrintableString { get { return (PrintableString)this[0]; } }
		public TeletexString   TeletexString   { get { return (TeletexString  )this[1]; } }
	}
}
