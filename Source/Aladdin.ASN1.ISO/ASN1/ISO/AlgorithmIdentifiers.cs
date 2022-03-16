using System;
using System.Runtime.Serialization;

// AlgorithmIdentifiers ::= SET OF AlgorithmIdentifier

namespace Aladdin.ASN1.ISO
{
	[Serializable]
	public class AlgorithmIdentifiers : Set<AlgorithmIdentifier>
	{
		// конструктор при сериализации
        protected AlgorithmIdentifiers(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public AlgorithmIdentifiers(IEncodable encodable) : base(encodable) {} 

		// конструктор при закодировании
		public AlgorithmIdentifiers(params AlgorithmIdentifier[] values) : base(values) {} 
	
		// найти требуемый атрибут
		public AlgorithmIdentifier this[string oid] { get 
		{
			// для всех атрибутов
			foreach (AlgorithmIdentifier algorithm in this)
			{
				// проверить совпадение идентификатора
				if (algorithm.Algorithm.Value == oid) return algorithm; 
			}
			return null; 
		}}
	}
}
