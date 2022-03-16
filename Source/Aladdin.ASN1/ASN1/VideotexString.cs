using System;
using System.IO;
using System.Text;
using System.Runtime.Serialization;

namespace Aladdin.ASN1
{
	//////////////////////////////////////////////////////////////////////////////
	// Строка символов Videotex
	//////////////////////////////////////////////////////////////////////////////
	[Serializable]
	public sealed class VideotexString : OctetString
	{
        // проверить допустимость типа
        public static new bool IsValidTag(Tag tag) { return tag == Tag.VideotexString; }
    
		// проверить корректность объекта
		public static void Validate(VideotexString encodable, bool encode, int min, int max) 
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
		public static void Validate(VideotexString encodable, bool encode, int min) 
		{
			// проверить корректность
			if (encodable != null && encodable.Value.Length < min) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
            }
		} 
		// конструктор при сериализации
        private VideotexString(SerializationInfo info, StreamingContext context) 

			// выполнить дополнительные вычисления 
			: base(info, context) { OnDeserialization(this); }

		// дополнительные вычисления при сериализации
		public new void OnDeserialization(object sender)
		{
			// раскодировать строку
			str = Encoding.Default.GetString(Content); 
		}
		// конструктор при раскодировании
		public VideotexString(IEncodable encodable) : base(encodable) { OnDeserialization(this); }

		// конструктор при закодировании
		public VideotexString(string value) : base(Tag.VideotexString, 
			
			// закодировать строку
			Encoding.Default.GetBytes(value)) { str = value; } 

		// строка символов
		public new string Value { get { return str; } } [NonSerialized] private string str; 
	}
}
