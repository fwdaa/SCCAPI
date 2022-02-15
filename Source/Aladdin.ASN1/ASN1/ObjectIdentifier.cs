using System;
using System.IO;
using System.Text;
using System.Globalization;
using System.Collections.Generic;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Идентификатор объекта
	///////////////////////////////////////////////////////////////////////////
	public class ObjectIdentifier : AsnObject
	{
        // проверить допустимость типа
        public static bool IsValidTag(Tag tag) { return tag == Tag.ObjectIdentifier; }
    
		// конструктор при раскодировании
		public ObjectIdentifier(IEncodable encodable) : base(encodable)
		{
			StringBuilder builder = new StringBuilder();

			// проверить корректность способа кодирования
			if (encodable.PC != PC.Primitive) throw new InvalidDataException();

			// проверить корректность объекта
			if (encodable.Content.Length == 0) throw new InvalidDataException();
			
			// проверить корректность объекта
			if ((encodable.Content[encodable.Content.Length - 1] & 0x80) != 0)
			{
				// при ошибке выбросить исключение
				throw new InvalidDataException();
			}
			// для всех байтов представления
			int count = 1; for (int i = 0; i < encodable.Content.Length; i++)
			{
				// подсчитать количество чисел идентификатора
				if ((encodable.Content[i] & 0x80) == 0) count++; 
			}
			// выделить память для идентификатора
			ids = new long[count]; int cb = 0;

			// для всех чисел идентификатора
			for (int i = 1; i < count; i++)
			{
				// для всех непоследних разрядов числа
				for (; (encodable.Content[cb] & 0x80) != 0; cb++, ids[i] <<= 7)
				{
					// учесть непоследние разряды числа
					ids[i] |= (byte)(encodable.Content[cb] & 0x7F);
				}
				// учесть последние разряды числа
				ids[i] |= encodable.Content[cb++];
			}
				 // извлечь первые два числа
			     if (ids[1] >= 80) { ids[0] = 2; ids[1] -= 80; }
			else if (ids[1] >= 40) { ids[0] = 1; ids[1] -= 40; }
 
			// для всех чисел идентификатора
			for (int i = 0; i < ids.Length - 1; i++)
			{
				// поместить число в строку
				builder.AppendFormat("{0}.", ids[i]); 
			}
			// поместить последнее число в строку
			value = builder.AppendFormat("{0}", ids[ids.Length - 1]).ToString(); 
		}
		// конструктор при закодировании
		public ObjectIdentifier(string value) : base(Tag.ObjectIdentifier) 
		{
			// указать начальные условия разбора строки
			int pos = 0; List<Int64> list = new List<Int64>(); 

			// до окончания строки идентификатора
			for (int start = 0; true; start = pos + 1)
			{
				// найти позицию разделителя в строке
				pos = value.IndexOf('.', start); if (pos >= 0)
				{
					// извлечь строку с числом идентификатора
					string substr = value.Substring(start, pos - start); 

					// проверить корректность числа
					list.Add(Int64.Parse(substr, NumberStyles.None));
				}
				else {
					// извлечь строку с числом идентификатора
					string substr = value.Substring(start); 

					// проверить корректность числа
					list.Add(Int64.Parse(substr, NumberStyles.None)); break;
				}
			}
			// сохранить значение идентификатора
			this.value = value; this.ids = list.ToArray(); 
		}
		// способ кодирования для DER-кодировки
		protected override PC DerPC { get { return PC.Primitive; } }

		// содержимое объекта
		protected override byte[] DerContent { get 
		{
			// вычислить конкатенацию первых двух чисел
			long number = ids[0] * 40 + ids[1]; int cb = 0;  

			// для всех чисел идентификатора
			for (int i = 1; i < ids.Length; i++, cb++)
			{
                // определить размер закодированного числа
				if (number >= 0x0100000000000000) cb += 8; else 
				if (number >= 0x0002000000000000) cb += 7; else 
				if (number >= 0x0000040000000000) cb += 6; else 
				if (number >= 0x0000000800000000) cb += 5; else 
				if (number >= 0x0000000010000000) cb += 4; else 
				if (number >= 0x0000000000200000) cb += 3; else 
				if (number >= 0x0000000000004000) cb += 2; else 
				if (number >= 0x0000000000000080) cb += 1;

				// перейти на следующее число
				if (i < ids.Length - 1) number = ids[i + 1]; 
			}
			// выделить память для кодирования
			byte[] content = new byte[cb]; 
 
			// вычислить конкатенацию первых двух чисел
			number = ids[0] * 40 + ids[1]; cb = 0;  

			// для всех чисел идентификатора
			for (int i = 1; i < ids.Length; i++)
			{
				// в зависимости от величины числа
				if (number >= 0x0100000000000000)
                {
					// закодировать часть числа
					content[cb++] = (byte)(((number & 0x7F00000000000000) >> 56) | 0x80);
                }
				// в зависимости от величины числа
				if (number >= 0x0002000000000000)
                {
					// закодировать часть числа
					content[cb++] = (byte)(((number & 0x00FE000000000000) >> 49) | 0x80);
                }
				// в зависимости от величины числа
				if (number >= 0x0000040000000000)
                {
					// закодировать часть числа
					content[cb++] = (byte)(((number & 0x0001FC0000000000) >> 42) | 0x80);
                }
				// в зависимости от величины числа
				if (number >= 0x0000000800000000)
                {
					// закодировать часть числа
					content[cb++] = (byte)(((number & 0x000003F800000000) >> 35) | 0x80);
                }
				// в зависимости от величины числа
				if (number >= 0x0000000010000000)
				{
					// закодировать часть числа
					content[cb++] = (byte)(((number & 0x00000007F0000000) >> 28) | 0x80);
				}
				// в зависимости от величины числа
				if (number >= 0x0000000000200000)
				{
					// закодировать часть числа
					content[cb++] = (byte)(((number & 0x000000000FE00000) >> 21) | 0x80);
				}
				// в зависимости от величины числа
				if (number >= 0x0000000000004000)
				{
					// закодировать часть числа
					content[cb++] = (byte)(((number & 0x00000000001FC000) >> 14) | 0x80);
				}
				// в зависимости от величины числа
				if (number >= 0x0000000000000080)
				{
					// закодировать часть числа
					content[cb++] = (byte)(((number & 0x0000000000003F80) >> 7) | 0x80);
				}
				// в зависимости от величины числа
				if (number >= 0x0000000000000000)
				{
					// закодировать часть числа
					content[cb++] = (byte)(((number & 0x000000000000007F) >> 0) | 0x00);
				}
				// перейти на следующее число
				if (i < ids.Length - 1) number = ids[i + 1]; 
			}
			return content; 
		}}
 		// идентификатор объекта
		public string Value { get { return value; } } 
			
		// идентификатор объекта в строковой и числовой форме
		private string value; private long[] ids; 
	}
}

