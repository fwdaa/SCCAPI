///////////////////////////////////////////////////////////////////////////////
// GostR3412-15-Encryption-Parameters ::= SEQUENCE
// {
//      ukm OCTET STRING
// }
///////////////////////////////////////////////////////////////////////////////
namespace Aladdin.ASN1.GOST
{
	public class GOSTR3412EncryptionParameters : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<OctetString>().Factory(), Cast.N), 
		}; 
		// конструктор при раскодировании
		public GOSTR3412EncryptionParameters(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public GOSTR3412EncryptionParameters(OctetString ukm) : base(info, ukm) {}

		public OctetString Ukm { get { return (OctetString)this[0]; } } 
	}

}
