using System;
using System.IO;
using System.Text;

namespace Aladdin.ASN1
{
	//////////////////////////////////////////////////////////////////////////////
	// Строка символов
	//////////////////////////////////////////////////////////////////////////////
	public class GeneralString : OctetString
	{
        // проверить допустимость типа
        public static new bool IsValidTag(Tag tag) { return tag == Tag.GeneralString; }
    
		// проверить корректность объекта
		public static void Validate(GeneralString encodable, bool encode, int min, int max) 
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
		public static void Validate(GeneralString encodable, bool encode, int min) 
		{
			// проверить корректность
			if (encodable != null && encodable.Value.Length < min) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
            }
		} 
		// конструктор при раскодировании
		public GeneralString(IEncodable encodable) : base(encodable) 
		{ 
			// раскодировать строку
			str = Encoding.Default.GetString(Content); 
		}
		// конструктор при закодировании
		public GeneralString(string value) : base(Tag.GeneralString, 
			
			// закодировать строку
			Encoding.Default.GetBytes(value)) { str = value; } 

		// строка символов
		public new string Value { get { return str; } } private string str; 
	}
}
