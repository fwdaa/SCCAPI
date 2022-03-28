using System;
using System.IO;
using System.Runtime.Serialization;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Строка битов
	///////////////////////////////////////////////////////////////////////////
	[Serializable]
	public class BitString : AsnObject
	{
        // проверить допустимость типа
        public static bool IsValidTag(Tag tag) { return tag == Tag.BitString; }
    
		// проверить корректность объекта
		public static void Validate(BitString encodable, bool encode, int min, int max) 
		{
			// проверить корректность
			if (encodable != null && encodable.Bits < min) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
            }
			// проверить корректность
			if (encodable != null && encodable.Bits > max) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
            }
		} 
		// проверить корректность объекта
		public static void Validate(BitString encodable, bool encode, int min) 
		{
			// проверить корректность
			if (encodable != null && encodable.Bits < min) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
            }
		} 
		// преобразовать значение во флаги
		public static long ToFlags(byte[] value, int bits)
		{ 
			// определить последний ненулевой байт
			int cb = value.Length; while (cb >= 1 && value[cb - 1] == 0) cb--; 
 
			// проверить наличие ненулевых байтов
			if (cb == 0) return 0; long numeric = 0;

			// для всех битов ненулевого байта
			for (int i = 0; i < 8; i++)
			{
				// извлечь бит
				byte bt = (byte)((value[cb - 1] >> i) & 0x1); 

				// установить число битов
				if (bits == 0 && bt != 0) bits = 8 * cb - i; 
				
				// изменить позицию бита
				numeric = (numeric << 1) | bt;
			}
			// для всех байтов 
			for (int i = cb - 2; i >= 0; i--)
			{
				// для всех битов
				for (int j = 0; j < 8; j++)
				{
					// извлечь бит
					byte bt = (byte)((value[i] >> j) & 0x1); 

					// изменить позицию бита
					numeric = numeric << 1 | bt;
				}
			}
			return numeric; 
		}
		// конструктор при сериализации
        protected BitString(SerializationInfo info, StreamingContext context) 
			
			// инициализировать объект
			: base(info, context) { Init(); } private void Init()
        {
			// проверить корректность объекта
			if (Content.Length == 0) throw new InvalidDataException();

			// проверить способ кодирования строки битов
			if (PC == PC.Primitive) 
			{
				// проверить корректность объекта
				if (Content[0] >= 8) throw new InvalidDataException();

				// для пустого объекта
				if (Content.Length == 1)
				{
					// проверить корректность объекта
					if (Content[0] > 0) throw new InvalidDataException();

					// проверить на пустую строку
					value = new byte[0]; bits = 0; return; 
				}
				// выделить память под строку битов
				int unused = Content[0]; value = new byte[Content.Length - 1];

				// определить число ненулевых битов 
				bits = 8 * (Content.Length - 1) - unused;

				// скопировать строку битов
				Array.Copy(Content, 1, value, 0, value.Length);

				// обнулить неиспользуемые биты
				value[(bits - 1) / 8] &= unchecked((byte)~((1 << unused) - 1)); return;
			}
			// задать начальные условия при перечислении внутренних объектов
			int length = Content.Length; value = new byte[0]; bits = 0; 

			// для всех внутренних объектов
			for (int cb = 0; length > 0; )
			{
				// раскодировать внутренний объект
				BitString inner = new BitString(Encodable.Decode(Content, cb, length));

				// проверить корректность объекта
				if ((inner.Bits % 8) != 0 && length != inner.Encoded.Length) 
				{
					// при ошибке выбросить исключение
					throw new InvalidDataException(); 
				}
				// изменить размер содержимого
				Array.Resize(ref value, value.Length + inner.Value.Length);

				// добавить содержимое внутреннего объекта
				Array.Copy(inner.Value, 0, value, value.Length - inner.Value.Length, inner.Value.Length);

				// перейти на следующий объект
				bits += inner.Bits; cb += inner.Encoded.Length; length -= inner.Encoded.Length;
			}
        }
		// конструктор при раскодировании
		public BitString(IEncodable encodable) : base(encodable) { Init(); }

		// конструктор при закодировании
		public BitString(byte[] value) : this(value, value.Length * 8) {} 

		// конструктор при закодировании
		public BitString(byte[] value, int bits) : base(Tag.BitString) 
		{
			// проверить на пустую строку
			if (bits == 0) { this.value = new byte[0]; this.bits = 0; return; }

			// определить число неиспользуемых битов
			int unused = ((bits % 8) != 0) ? 8 - (bits % 8) : 0; 

			// выделить память под строку битов
			this.value = new byte[(bits + 7) / 8]; this.bits = bits; 

			// скопировать строку битов
			Array.Copy(value, this.value, this.value.Length);

			// обнулить неиспользуемые биты
			this.value[(bits - 1) / 8] &= unchecked((byte)~((1 << unused) - 1)); 
		}
		// конструктор при закодировании
		public BitString(Math.BigInteger number, int bits) : base(Tag.BitString) 
		{
			// проверить корректность числа
			if (number.Signum == -1) throw new ArgumentOutOfRangeException(); 

			// определить число неиспользуемых битов
			this.bits = bits; int unused = ((bits % 8) != 0) ? 8 - bits % 8 : 0; 

			// закодировать большое число
			byte[] encoded = number.ShiftLeft(unused).ToByteArray();

            // проверить необходимость переразмещения
            if (encoded.Length == 1 || encoded[0] != 0) this.value = encoded; 
		    else {
			    // переразместить буфер
			    this.value = new byte[encoded.Length - 1];

			    // скопировать значимые данные
			    Array.Copy(encoded, 1, this.value, 0, encoded.Length - 1); 
		    }
		}
		// способ кодирования для DER-кодировки
		protected override PC DerPC { get { return PC.Primitive; } }

		// содержимое объекта
		protected override byte[] DerContent { get 
		{ 
			// выделить память для кодирования
			byte[] content = new byte[value.Length + 1];
 
			// закодировать неиспользуемое число битов
			content[0] = (byte)(8 * value.Length - bits); 

			// закодировать строку битов
			Array.Copy(value, 0, content, 1, value.Length); return content; 
		}}
 		// строка битов и их количество
		public byte[] Value { get { return value; } }
		public int    Bits  { get { return bits;  } } 

		// раскодировать большое число
		public Math.BigInteger ToBigInteger()
		{
			// определить число неиспользуемых битов
			int unused = value.Length * 8 - bits; 

			// раскодировать большое число
			return new Math.BigInteger(1, value).ShiftRight(unused); 
		}
		// строка битов и их количество
		[NonSerialized] protected byte[] value; [NonSerialized] protected int bits; 
	}
}
