using System;
using System.IO;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Булевое значение
	///////////////////////////////////////////////////////////////////////////
	public class Boolean : AsnObject
	{
        // проверить допустимость типа
        public static bool IsValidTag(Tag tag) { return tag == Tag.Boolean; }
    
		// булевы значения 
		public static readonly Boolean True  = new Boolean(true );
		public static readonly Boolean False = new Boolean(false); 

		// конструктор при раскодировании
		public Boolean(IEncodable encodable) : base(encodable)
		{
			// проверить корректность способа кодирования
			if (encodable.PC != PC.Primitive) throw new InvalidDataException();

			// проверить корректность объекта
			if (encodable.Content.Length != 1) throw new InvalidDataException();

			// сохранить булевое значение
			this.value = (encodable.Content[0] != 0); 
		}
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
		public bool Value { get { return value; } } private bool value;
	}
}
