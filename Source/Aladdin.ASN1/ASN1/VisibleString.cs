using System;
using System.IO;
using System.Text;

namespace Aladdin.ASN1
{
	//////////////////////////////////////////////////////////////////////////////
	// Строка символов ISO-646
	//////////////////////////////////////////////////////////////////////////////
	public class VisibleString : OctetString
	{
        // проверить допустимость типа
        public static new bool IsValidTag(Tag tag) { return tag == Tag.VisibleString; }
    
		// проверить корректность объекта
		public static void Validate(VisibleString encodable, bool encode, int min, int max) 
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
		public static void Validate(VisibleString encodable, bool encode, int min) 
		{
			// проверить корректность
			if (encodable != null && encodable.Value.Length < min) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
            }
		} 
		// конструктор при раскодировании
		public VisibleString(IEncodable encodable) : base(encodable) 
		{ 
			// раскодировать строку
			str = Encoding.ASCII.GetString(Content); 
		}
		// конструктор при закодировании
		protected VisibleString(Tag tag, string value) : base(tag, 
			
			// закодировать строку
			Encoding.ASCII.GetBytes(value)) { str = value; }

		// конструктор при закодировании
		public VisibleString(string value) : this(Tag.VisibleString, value) {}

		// строка символов
		public new string Value { get { return str; } } private string str; 
	}
}
