using System;
using System.IO;
using System.Text;
using System.Runtime.Serialization;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Строка числовых символов
	///////////////////////////////////////////////////////////////////////////
	[Serializable]
	public class NumericString : OctetString
	{
        // проверить допустимость типа
        public static new bool IsValidTag(Tag tag) { return tag == Tag.NumericString; }
    
		// проверить корректность объекта
		public static void Validate(NumericString encodable, bool encode, int min, int max) 
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
		public static void Validate(NumericString encodable, bool encode, int min) 
		{
			// проверить корректность
			if (encodable != null && encodable.Value.Length < min) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
            }
		} 
		// конструктор при сериализации
        protected NumericString(SerializationInfo info, StreamingContext context) 

			// инициализировать объект
			: base(info, context) { Init(); } private void Init()
		{
			// раскодировать строку
			str = Encoding.ASCII.GetString(Content); 
		}
		// конструктор при раскодировании
		public NumericString(IEncodable encodable) : base(encodable) { Init(); }

		// конструктор при закодировании
		public NumericString(string value) : base(Tag.NumericString, 
			
			// закодировать строку
			Encoding.ASCII.GetBytes(value)) { str = value; } 

		// строка символов
		public new string Value { get { return str; } } [NonSerialized] private string str; 
	}
}
