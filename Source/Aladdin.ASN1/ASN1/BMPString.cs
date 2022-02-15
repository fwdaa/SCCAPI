using System;
using System.IO;
using System.Text;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Строка двухбайтовых символов Unicode
	///////////////////////////////////////////////////////////////////////////
	public class BMPString : OctetString
	{
        // проверить допустимость типа
        public static new bool IsValidTag(Tag tag) { return tag == Tag.BMPString; }
    
		// проверить корректность объекта
		public static void Validate(BMPString encodable, bool encode, int min, int max) 
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
		public static void Validate(BMPString encodable, bool encode, int min) 
		{
			// проверить корректность
			if (encodable != null && encodable.Value.Length < min) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
            }
		} 
		// конструктор при раскодировании
		public BMPString(IEncodable encodable) : base(encodable) 
		{ 
			// раскодировать строку
			str = Encoding.BigEndianUnicode.GetString(Content); 
		}
		// конструктор при закодировании
		public BMPString(string value) : base(Tag.BMPString, 
			
			// закодировать строку
			Encoding.BigEndianUnicode.GetBytes(value)) { str = value; } 

		// строка символов
		public new string Value { get { return str; } } private string str; 
	}
}
