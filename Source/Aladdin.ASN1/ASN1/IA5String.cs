using System;
using System.IO;
using System.Text;
using System.Runtime.Serialization;

namespace Aladdin.ASN1
{
	//////////////////////////////////////////////////////////////////////////////
	// Строка символов ASCII
	//////////////////////////////////////////////////////////////////////////////
	[Serializable]
	public sealed class IA5String : OctetString
	{
        // проверить допустимость типа
        public static new bool IsValidTag(Tag tag) { return tag == Tag.IA5String; }
    
		// проверить корректность объекта
		public static void Validate(IA5String encodable, bool encode, int min, int max) 
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
		public static void Validate(IA5String encodable, bool encode, int min) 
		{
			// проверить корректность
			if (encodable != null && encodable.Value.Length < min) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
            }
		} 
		// конструктор при сериализации
        private IA5String(SerializationInfo info, StreamingContext context) 

			// инициализировать объект
			: base(info, context) { Init(); } private void Init()
		{
			// раскодировать строку
			str = Encoding.ASCII.GetString(Content); 
		}
		// конструктор при раскодировании
		public IA5String(IEncodable encodable) : base(encodable) { Init(); }

		// конструктор при закодировании
		public IA5String(string value) : base(Tag.IA5String, 
			
			// закодировать строку
			Encoding.ASCII.GetBytes(value)) { str = value; } 

		// строка символов
		public new string Value { get { return str; } } [NonSerialized] private string str; 
	}
}
