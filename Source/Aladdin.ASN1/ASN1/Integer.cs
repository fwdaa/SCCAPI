using System;
using System.IO;
using System.Runtime.Serialization;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Целое число со знаком
	///////////////////////////////////////////////////////////////////////////
	[Serializable]
	public class Integer : AsnObject
	{
        // проверить допустимость типа
        public static bool IsValidTag(Tag tag) { return tag == Tag.Integer; }
    
		// проверить корректность объекта
		public static void Validate(Integer encodable, bool encode, int min, int max) 
		{
			// проверить корректность
			if (encodable != null && encodable.Value.IntValue < min) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
            }
			// проверить корректность
			if (encodable != null && encodable.Value.IntValue > max) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
            }
		} 
		// проверить корректность объекта
		public static void Validate(Integer encodable, bool encode, int min) 
		{
			// проверить корректность
			if (encodable != null && encodable.Value.IntValue < min) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
            }
		} 
		// конструктор при сериализации
        protected Integer(SerializationInfo info, StreamingContext context)

			// инициализировать объект
			: base(info, context) { Init(); } private void Init()
        {
			// проверить корректность способа кодирования
			if (PC != PC.Primitive) throw new InvalidDataException();

			// проверить корректность объекта
			if (Content.Length == 0) throw new InvalidDataException();

			// раскодировать целое число со знаком
			this.value = new Math.BigInteger(Content);  
        }
		// конструктор при раскодировании
		public Integer(IEncodable encodable) : base(encodable) { Init(); }

		// конструктор при закодировании
		protected Integer(Tag tag, Math.BigInteger value) : base(tag        ) { this.value = value; }
		public    Integer(         Math.BigInteger value) : base(Tag.Integer) { this.value = value; }
		
		// конструктор при закодировании
		protected Integer(Tag tag, int value) : this(tag, Math.BigInteger.ValueOf(value))  {} 
		public    Integer(         int value) : this(     Math.BigInteger.ValueOf(value))  {} 

		// конструктор при закодировании
		protected Integer(Tag tag, Enum value) : this(tag, Convert.ToInt32(value)) {}
		public    Integer(         Enum value) : this(     Convert.ToInt32(value)) {}

		// способ кодирования для DER-кодировки
		protected override PC DerPC { get { return PC.Primitive; } }

		// содержимое объекта
		protected override byte[] DerContent { get { return value.ToByteArray(); } }

 		// целое число со знаком
		public Math.BigInteger Value { get { return value; } } 

		// целое число со знаком
		public int IntValue { get { return Value.IntValue; } } 

		// раскодированное значение
		[NonSerialized] private Math.BigInteger value;
	}
}
