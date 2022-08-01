using System;
using System.Runtime.Serialization;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Значение перечислимого типа
	///////////////////////////////////////////////////////////////////////////
	[Serializable]
	public sealed class Enumerated<T> : Integer where T : struct
	{
        // проверить допустимость типа
        public static new bool IsValidTag(Tag tag) { return tag == Tag.Enumerated; }
    
		// конструктор при сериализации
        private Enumerated(SerializationInfo info, StreamingContext context) : base(info, context) {} 

		// конструктор при раскодировании
		public Enumerated(IEncodable encodable) : base(encodable) {}

		// конструктор при закодировании
		public Enumerated(Math.BigInteger value) : base(Tag.Enumerated, value) {}
		
		// конструктор при закодировании
		public Enumerated(int value) : this(Math.BigInteger.ValueOf(value))  {} 

		// конструктор при закодировании
		public Enumerated(T value) : this(Convert.ToInt32(value)) {}

 		// целое число со знаком
		public new T Value { get { return (T)(object)base.IntValue; } } 
	}
}
