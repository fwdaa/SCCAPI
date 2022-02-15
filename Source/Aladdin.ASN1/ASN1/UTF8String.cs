using System;
using System.IO;
using System.Text;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Строка символов UTF-8
	///////////////////////////////////////////////////////////////////////////
	public class UTF8String : OctetString
	{
        // проверить допустимость типа
        public static new bool IsValidTag(Tag tag) { return tag == Tag.UTF8String; }
    
		// проверить корректность объекта
		public static void Validate(UTF8String encodable, bool encode, int min, int max) 
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
		public static void Validate(UTF8String encodable, bool encode, int min) 
		{
			// проверить корректность
			if (encodable != null && encodable.Value.Length < min) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
            }
		} 
		// конструктор при раскодировании
		public UTF8String(IEncodable encodable) : base(encodable) 
		{ 
			// раскодировать строку
			str = Encoding.UTF8.GetString(Content); 
		}
		// конструктор при закодировании
		public UTF8String(string value) : base(Tag.UTF8String, 
			
			// закодировать строку
			Encoding.UTF8.GetBytes(value)) { str = value; } 

		// строка символов
		public new string Value { get { return str; } } private string str; 
	}
}
