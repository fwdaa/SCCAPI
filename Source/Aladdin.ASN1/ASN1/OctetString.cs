using System;
using System.IO;
using System.Runtime.Serialization;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Строка байтов
	///////////////////////////////////////////////////////////////////////////
	[Serializable]
	public class OctetString : AsnObject
	{
        // проверить допустимость типа
        public static bool IsValidTag(Tag tag) { return tag == Tag.OctetString; }
    
		// проверить корректность объекта
		public static void Validate(OctetString encodable, bool encode, int min, int max) 
		{
			// проверить корректность
			if (encodable != null && encodable.Value.Length < min) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
            }
			// проверить корректность
			if (encodable != null && encodable.Value.Length > max) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
            }
		} 
		// проверить корректность объекта
		public static void Validate(OctetString encodable, bool encode, int min) 
		{
			// проверить корректность
			if (encodable != null && encodable.Value.Length < min) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
            }
		} 
		// конструктор при сериализации
        protected OctetString(SerializationInfo info, StreamingContext context)

			// инициализировать объект
			: base(info, context) { Init(); } private void Init()
        {
			// проверить способ кодирования строки байтов
			if (PC == PC.Primitive) { value = Content; return; }

			// задать начальные условия при перечислении внутренних объектов
			int length = Content.Length; value = new byte[0];  

			// для всех внутренних объектов
			for (int cb = 0; length > 0; )
			{
				// раскодировать внутренний объект
				OctetString inner = new OctetString(Encodable.Decode(Content, cb, length));

				// изменить размер содержимого
				Array.Resize(ref value, value.Length + inner.Value.Length); 

				// добавить содержимое внутреннего объекта
				Array.Copy(inner.Value, 0, value, value.Length - inner.Value.Length, inner.Value.Length); 

				// перейти на следующий объект
				cb += inner.Encoded.Length; length -= inner.Encoded.Length; 
			}
        }
		// конструктор при раскодировании
		public OctetString(IEncodable encodable) : base(encodable) { Init(); }

		// конструктор при закодировании
		protected OctetString(Tag tag, byte[] value, int ofs, int cb) : base(tag) 
		{
			// сохранить строку байтов
			this.value = new byte[cb]; Array.Copy(value, ofs, this.value, 0, cb); 
		}
		// конструктор при закодировании
		protected OctetString(Tag tag, byte[] value) : this(tag, value, 0, value.Length) { } 

		// конструктор при закодировании
		public OctetString(byte[] value, int ofs, int cb) : this(Tag.OctetString, value, ofs, cb) {} 

		// конструктор при закодировании
		public OctetString(byte[] value) : this(value, 0, value.Length) {} 

		// способ кодирования для DER-кодировки
		protected override PC DerPC { get { return PC.Primitive; } }

		// содержимое объекта
		protected override byte[] DerContent { get { return value; } }

 		// строка байтов
		public byte[] Value { get { return value; } } [NonSerialized] protected byte[] value;
	}
}
