using System;
using System.Runtime.Serialization;

// SMIMECapabilities ::= SEQUENCE OF SMIMECapability

namespace Aladdin.ASN1.ISO.PKCS.PKCS9
{
	[Serializable]
	public class SMIMECapabilities : Sequence<SMIMECapability>
	{
		// конструктор при сериализации
        protected SMIMECapabilities(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public SMIMECapabilities(IEncodable encodable) : base(encodable) {} 

		// конструктор при закодировании
		public SMIMECapabilities(params SMIMECapability[] values) : base(values) {} 
	
		// найти требуемый атрибут
		public SMIMECapability this[string oid] { get 
		{
			// для всех атрибутов
			foreach (SMIMECapability capability in this)
			{
				// проверить совпадение идентификатора
				if (capability.Algorithm.Value == oid) return capability; 
			}
			return null; 
		}}
	}
}
