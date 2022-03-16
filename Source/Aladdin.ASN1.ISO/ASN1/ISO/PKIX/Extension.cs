using System;
using System.Runtime.Serialization;

//	Extension  ::=  SEQUENCE  {
//		extnID      OBJECT IDENTIFIER,
//		critical    BOOLEAN DEFAULT FALSE,
//		extnValue   OCTET STRING
//	}

namespace Aladdin.ASN1.ISO.PKIX
{
	[Serializable]
	public class Extension : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier	>().Factory(), Cast.N, Tag.Any					), 
			new ObjectInfo(new ObjectCreator<Boolean			>().Factory(), Cast.O, Tag.Any,	Boolean.False	), 
			new ObjectInfo(new ObjectCreator<OctetString		>().Factory(), Cast.N, Tag.Any					), 
		}; 
		// конструктор при сериализации
        protected Extension(SerializationInfo info, StreamingContext context) : base(info, context) 
		{
			// раскодировать атрибут
			decoded = Encodable.Decode(this[2].Content); 
		}
		// конструктор при раскодировании
		public Extension(IEncodable encodable) : base(encodable, info) 
		{
			// раскодировать атрибут
			decoded = Encodable.Decode(this[2].Content); 
		}
		// конструктор при закодировании
		public Extension(ObjectIdentifier extnID, Boolean critical, IEncodable extnValue) : 
			base(info, extnID, critical, new OctetString(extnValue.Encoded)) 
		{
			// раскодировать атрибут
			decoded = extnValue; 
		}
		public ObjectIdentifier	ExtnID		{ get { return (ObjectIdentifier)this[0]; } } 
		public Boolean			Critical	{ get { return (Boolean         )this[1]; } }

		// раскодированное значение атрибута
		public IEncodable ExtnValue { get { return decoded; } } [NonSerialized] private IEncodable decoded; 
	}
}

