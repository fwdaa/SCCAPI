namespace Aladdin.ASN1.GOST
{
	public class GOSTR3410PrivateKeyValueInfo : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<OctetString>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<OctetString>().Factory(), Cast.N), 
		}; 
		// конструктор при раскодировании
		public GOSTR3410PrivateKeyValueInfo(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public GOSTR3410PrivateKeyValueInfo(OctetString privateKeyMaskValue, 
			OctetString publicKeyValue) : base(info, privateKeyMaskValue, publicKeyValue) {}

		public OctetString PrivateKeyMaskValue { get { return (OctetString)this[0]; } } 
		public OctetString PublicKeyValue      { get { return (OctetString)this[1]; } }
	}
}
