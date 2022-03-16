using System;
using System.Runtime.Serialization; 

//	KeyTransfer ::= SEQUENCE {
//		keyTransferContent		KeyTransferContent,
//		macKeyTransferContent	OCTET STRING (4)
//	}

namespace Aladdin.ASN1.GOST
{
    [Serializable]
	public class CryptoProKeyTransfer : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<CryptoProKeyTransferContent>().Factory(), Cast.N,	Tag.Any), 
			new ObjectInfo(new ObjectCreator<OctetString		        >().Factory(), Cast.N,	Tag.Any), 
		}; 
		// конструктор при сериализации
        protected CryptoProKeyTransfer(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public CryptoProKeyTransfer(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public CryptoProKeyTransfer(CryptoProKeyTransferContent keyTransferContent, OctetString macKeyTransferContent) : 
			base(info, keyTransferContent, macKeyTransferContent) {}
  
		public CryptoProKeyTransferContent	KeyTransferContent		{ get { return (CryptoProKeyTransferContent	)this[0]; } }
		public OctetString					MacKeyTransferContent	{ get { return (OctetString					)this[1]; } } 
	}
}
