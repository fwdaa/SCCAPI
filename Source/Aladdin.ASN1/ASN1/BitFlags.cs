using System;
using System.Runtime.Serialization;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Строка флагов
	///////////////////////////////////////////////////////////////////////////
	[Serializable]
	public sealed class BitFlags : BitString
	{
		// численное значение
		[NonSerialized] private Int64 numeric; 

		// конструктор при сериализации
        private BitFlags(SerializationInfo info, StreamingContext context) 
			
			// инициализировать объект
			: base(info, context) { Init(); } private void Init()		
		{
			// определить последний ненулевой байт
			int cb = value.Length; while (cb >= 1 && value[cb - 1] == 0) cb--; 
 
			// прочитать закодированное значение
			Array.Resize(ref value, cb); numeric = BitString.ToFlags(value, bits); 
		}
		// конструктор при раскодировании
		public BitFlags(IEncodable encodable) : base(encodable) { Init(); }

		// конструктор при закодировании
		public BitFlags(Int64 flags) : base(new byte[8], 64) 
		{
			// для всех байтов
			for (int i = 0; i < 8; i++)
			{
				// извлечь байт
				byte b = (byte)((flags >> (8 * i)) & 0xFF); 

				// для всех битов
				for (int j = 0; j < 8; j++)
				{
					// извлечь бит
					byte bt = (byte)((b >> j) & 0x1); 

					// изменить позицию бита
					value[i] |= (byte)(bt << (7 - j)); 
				}
			}
			// определить последний ненулевой байт
			int cb = 8; while (cb >= 1 && value[cb - 1] == 0) cb--;
 
			// проверить наличие ненулевых байтов
			if (cb == 0) { value = new byte[0]; bits = 0; return; }

			// изменить размер массива
			Array.Resize(ref value, cb);  

			// для всех битов ненелевого байта
			for (int i = 0; i < 8; i++)
			{
				// найти ненулевой бит
				if ((value[cb - 1] & (1 << i)) == 0) continue; 

				// установить число битов
				bits = 8 * cb - i; return; 
			}
		}
		// конструктор при закодировании
		public BitFlags(Enum flags) : this(Convert.ToInt64(flags)) {} 

		// содержимое объекта
		protected override byte[] DerContent { get 
		{ 
			// выделить память для кодирования
			byte[] content = new byte[(bits + 15) / 8];
 
			// закодировать неиспользуемое число битов
			content[0] = (byte)((bits % 8) != 0 ? 8 - bits % 8 : 0); 

			// закодировать строку битов
			Array.Copy(value, 0, content, 1, content.Length - 1); return content; 
		}}
		// численное представление
		public new Int64 Value { get { return numeric; } } 
	}
}
