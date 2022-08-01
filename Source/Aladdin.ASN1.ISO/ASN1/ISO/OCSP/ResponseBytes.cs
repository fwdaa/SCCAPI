using System;
using System.Runtime.Serialization;

// ResponseBytes ::= SEQUENCE {
//     responseType  RESPONSE.&id ({ResponseSet}),
//     response      OCTET STRING (CONTAINING RESPONSE.&Type({ResponseSet}{@responseType}))
// }

namespace Aladdin.ASN1.ISO.OCSP
{
	[Serializable]
	public class ResponseBytes : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<OctetString     >().Factory(), Cast.N) 
		}; 
		// конструктор при сериализации
        protected ResponseBytes(SerializationInfo info, StreamingContext context) 
			
		// инициализировать объект
			: base(info, context) { Init(); } private void Init()
        {
			// раскодировать атрибут
			decoded = Encodable.Decode(this[1].Content); 
        }
		// конструктор при раскодировании
		public ResponseBytes(IEncodable encodable) : base(encodable, info) { Init(); } 

		// конструктор при закодировании
		public ResponseBytes(ObjectIdentifier responseType, IEncodable response) : 
			base(info, responseType, new OctetString(response.Encoded)) { decoded = response; } 

		public ObjectIdentifier ResponseType { get { return (ObjectIdentifier)this[0]; } } 

		// раскодированное значение 
		public IEncodable Response { get { return decoded; }} [NonSerialized] private IEncodable decoded;
	}
}
