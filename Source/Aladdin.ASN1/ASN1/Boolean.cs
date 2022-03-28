using System;
using System.IO;
using System.Runtime.Serialization;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Булевое значение
	///////////////////////////////////////////////////////////////////////////
	[Serializable]
	public sealed class Boolean : AsnObject
	{
        // проверить допустимость типа
        public static bool IsValidTag(Tag tag) { return tag == Tag.Boolean; }
    
		// булевы значения 
		public static readonly Boolean True  = new Boolean(true );
		public static readonly Boolean False = new Boolean(false); 

		// конструктор при сериализации
        private Boolean(SerializationInfo info, StreamingContext context) 
		
			// инициализировать объект
			: base(info, context) { Init(); } private void Init()
        {
			// проверить корректность способа кодирования
			if (PC != PC.Primitive) throw new InvalidDataException();

			// проверить корректность объекта
			if (Content.Length != 1) throw new InvalidDataException();

			// сохранить булевое значение
			this.value = (Content[0] != 0); 
        }
		// конструктор при раскодировании
		public Boolean(IEncodable encodable) : base(encodable) { Init(); }

		// конструктор при закодировании
		public Boolean(bool value) : base(Tag.Boolean) { this.value = value; }

		// способ кодирования для DER-кодировки
		protected override PC DerPC { get { return PC.Primitive; } }

		// содержимое объекта
		protected override byte[] DerContent { get 
		{
			// вернуть содержимое объекта
			return new byte[] { value ? (byte)0xFF : (byte)0x00 } ; 
		}}
 		// булевое значение
		public bool Value { get { return value; } } [NonSerialized] private bool value;
	}
}
