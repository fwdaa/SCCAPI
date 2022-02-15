using System;

//	IssuerSerial  ::=  SEQUENCE {
//		issuer    GeneralNames,
//		serial    INTEGER,
//		issuerUID BIT STRING OPTIONAL
//}

namespace Aladdin.ASN1.ISO.PKIX
{
	public class IssuerSerial : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<GeneralNames	>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer		>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<BitString	    >().Factory(), Cast.O), 
		}; 
		// конструктор при раскодировании
		public IssuerSerial(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public IssuerSerial(GeneralNames issuer, Integer serial, 
			BitString issuerUID) : base(info, issuer, serial, issuerUID) {}

		public GeneralNames Issuer		{ get { return (GeneralNames)this[0]; }} 
		public Integer		Serial		{ get { return (Integer		)this[1]; }}
		public BitString	IssuerUID	{ get { return (BitString	)this[2]; }}
	}
}
