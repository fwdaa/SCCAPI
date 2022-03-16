using System;
using System.IO;
using System.Text;
using System.Runtime.Serialization;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Строка символов UTF-32
	///////////////////////////////////////////////////////////////////////////
	[Serializable]
	public sealed class UniversalString : OctetString
	{
        // проверить допустимость типа
        public static new bool IsValidTag(Tag tag) { return tag == Tag.UniversalString; }
    
		// проверить корректность объекта
		public static void Validate(UniversalString encodable, bool encode, int min, int max) 
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
		public static void Validate(UniversalString encodable, bool encode, int min) 
		{
			// проверить корректность
			if (encodable != null && encodable.Value.Length < min) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
            }
		} 
		// конструктор при сериализации
        private UniversalString(SerializationInfo info, StreamingContext context) 

			// выполнить дополнительные вычисления 
			: base(info, context) { OnDeserialization(this); }

		// дополнительные вычисления при сериализации
		public new void OnDeserialization(object sender)
		{
			// выделить память для изменения порядка байтов
			byte[] content = new byte[value.Length]; 

			// для всех закодированных символов
			for (int i = 0; i < content.Length / 4; i++)
			{
				// изменить порядок следования элементов
				content[4 * i + 0] = value[4 * i + 3]; content[4 * i + 1] = value[4 * i + 2];
				content[4 * i + 2] = value[4 * i + 1]; content[4 * i + 3] = value[4 * i + 0];
			}
			// раскодировать строку
			str = Encoding.UTF32.GetString(content); 
		}
		// конструктор при раскодировании
		public UniversalString(IEncodable encodable) : base(encodable) { OnDeserialization(this); }

		// конструктор при закодировании
		public UniversalString(string str) : base(Tag.UniversalString, Encoding.UTF32.GetBytes(str)) 
		{ 
			// для всех закодированных символов
			this.str = str; for (int i = 0; i < value.Length / 4; i++)
			{
				// изменить порядок следования элементов
				value[4 * i + 0] ^= value[4 * i + 3]; value[4 * i + 1] ^= value[4 * i + 2];
				value[4 * i + 3] ^= value[4 * i + 0]; value[4 * i + 2] ^= value[4 * i + 1];
				value[4 * i + 0] ^= value[4 * i + 3]; value[4 * i + 1] ^= value[4 * i + 2];
			}
		} 
		// строка символов
		public new string Value { get { return str; } } [NonSerialized] private string str; 
	}
}
