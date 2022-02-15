using System;

//	PresentationAddress ::= SEQUENCE {
//		pSelector     [0] EXPLICIT OCTET STRING OPTIONAL,
//		sSelector     [1] EXPLICIT OCTET STRING OPTIONAL,
//		tSelector     [2] EXPLICIT OCTET STRING OPTIONAL,
//		nAddresses    [3] EXPLICIT Addresses 
// }

namespace Aladdin.ASN1.ISO.PKIX.X400
{
	public class PresentationAddress : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<OctetString>().Factory(), Cast.EO, Tag.Context(0)), 
			new ObjectInfo(new ObjectCreator<OctetString>().Factory(), Cast.EO, Tag.Context(1)), 
			new ObjectInfo(new ObjectCreator<OctetString>().Factory(), Cast.EO, Tag.Context(2)), 
			new ObjectInfo(new ObjectCreator<Addresses	>().Factory(), Cast.E,  Tag.Context(3)), 
		}; 
		// конструктор при раскодировании
		public PresentationAddress(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public PresentationAddress(OctetString pSelector, OctetString sSelector,
			OctetString tSelector, Addresses nAddresses) : 
			base(info, pSelector, sSelector, tSelector, nAddresses) {}

		public OctetString	PSelector	{ get { return (OctetString )this[0]; } }
		public OctetString	SSelector	{ get { return (OctetString )this[1]; } }
		public OctetString	TSelector	{ get { return (OctetString )this[2]; } }
		public Addresses	NAddresses	{ get { return (Addresses	)this[3]; } }
	}
}
