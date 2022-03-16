using System;
using System.IO;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Тип объекта
	///////////////////////////////////////////////////////////////////////////
    [Serializable]
	public struct Tag : IEquatable<Tag>, IComparable<Tag>
	{
		// тип объекта заданного класса
		public static Tag Universal  (int value) { return new Tag(TagClass.Universal,   value); }
		public static Tag Application(int value) { return new Tag(TagClass.Application, value); }
		public static Tag Context	 (int value) { return new Tag(TagClass.Context,		value); }
		public static Tag Private	 (int value) { return new Tag(TagClass.Private,		value); }

		// известные типы объектов
		public static readonly Tag Any				= Universal( 0);
		public static readonly Tag Boolean			= Universal( 1);
		public static readonly Tag Integer			= Universal( 2);
		public static readonly Tag BitString		= Universal( 3);
		public static readonly Tag OctetString		= Universal( 4);
		public static readonly Tag Null				= Universal( 5);
		public static readonly Tag ObjectIdentifier = Universal( 6);
		public static readonly Tag ObjectDescriptor = Universal( 7);
		public static readonly Tag External         = Universal( 8);
		public static readonly Tag Real             = Universal( 9);
		public static readonly Tag Enumerated       = Universal(10);
		public static readonly Tag EmbeddedPDV      = Universal(11);
		public static readonly Tag UTF8String		= Universal(12);
		public static readonly Tag RelativeOID   	= Universal(13);
		public static readonly Tag Sequence			= Universal(16);
		public static readonly Tag Set				= Universal(17);
		public static readonly Tag NumericString	= Universal(18);
		public static readonly Tag PrintableString	= Universal(19);
		public static readonly Tag TeletexString	= Universal(20);
		public static readonly Tag VideotexString	= Universal(21);
		public static readonly Tag IA5String		= Universal(22);
		public static readonly Tag UTCTime			= Universal(23);
		public static readonly Tag GeneralizedTime	= Universal(24);
		public static readonly Tag GraphicString	= Universal(25);
		public static readonly Tag VisibleString	= Universal(26);
		public static readonly Tag GeneralString	= Universal(27);
		public static readonly Tag UniversalString	= Universal(28);
		public static readonly Tag CharacterString	= Universal(29);
		public static readonly Tag BMPString		= Universal(30);

		// сравнить два типа
		public static bool operator == (Tag A, Tag B) { return  A.Equals(B); }
		public static bool operator != (Tag A, Tag B) { return !A.Equals(B); }

		// сравнить два типа
        public static bool operator <= (Tag A, Tag B) { return A.CompareTo(B) <= 0; }
		public static bool operator >= (Tag A, Tag B) { return A.CompareTo(B) >= 0; }
		public static bool operator <  (Tag A, Tag B) { return A.CompareTo(B) <  0; }
		public static bool operator >  (Tag A, Tag B) { return A.CompareTo(B) >  0; }

        // класс объекта и тип объекта
		public readonly TagClass Class; public readonly int Value;		

        // конструктор
		public Tag(TagClass tagClass, int value) { Class = tagClass; Value = value; }

		// получить хэш-код типа
		public override int GetHashCode() { return (int)Class ^ Value; }

		// сравнить два типа
		public override bool Equals(object other)
		{
			// сравнить два типа
			return (other is Tag) ? Equals((Tag)other) : false;
		}
		// сравнить два типа
		public bool Equals(Tag other)
		{
			// сравнить два типа
			return Class == other.Class && Value == other.Value;
		}
		// сравнить два типа
		public int CompareTo(Tag other)
		{
            // сравнить значения
            if (Class == other.Class) return Value - other.Value; 

			// сравнить классы
			return (int)Class - (int)other.Class; 
		}
        ///////////////////////////////////////////////////////////////////////
        // Кодирование типа
        ///////////////////////////////////////////////////////////////////////
        public byte[] Encode(PC pc) { byte[] encoded = null; 

		    // учесть размер типа объекта
			if (Value >= 0x10000000) encoded = new byte[6]; else 
			if (Value >= 0x00200000) encoded = new byte[5]; else 
			if (Value >= 0x00004000) encoded = new byte[4]; else 
			if (Value >= 0x00000080) encoded = new byte[3]; else 
			if (Value >= 0x0000001F) encoded = new byte[2]; else 
                                     encoded = new byte[1];

			// записать первый байт типа объекта
			encoded[0] = (byte)((int)Class << 6);

			// закодировать способ кодирования
			if (pc == PC.Constructed) encoded[0] |= 0x20;

			// закодировать первый байт типа объекта
			encoded[0] |= (Value < 0x1F) ? (byte)Value : (byte)0x1F;

			// для длинного типа объекта
			int cb = 1; if (Value >= 0x10000000)
			{
				// закодировать часть типа
				encoded[cb++] = (byte)(((Value & 0x70000000) >> 28) | 0x80);
			}
			// для длинного типа
			if (Value >= 0x00200000)
			{
				// закодировать часть типа
				encoded[cb++] = (byte)(((Value & 0x0FE00000) >> 21) | 0x80);
			}
			// для длинного типа
			if (Value >= 0x00004000)
			{
				// закодировать часть типа
				encoded[cb++] = (byte)(((Value & 0x001FC000) >> 14) | 0x80);
			}
			// для длинного типа
			if (Value >= 0x00000080)
			{
				// закодировать часть типа
				encoded[cb++] = (byte)(((Value & 0x00003F80) >> 7) | 0x80);
			}
			// для длинного типа
			if (Value >= 0x0000001F)
			{
				// закодировать часть типа
				encoded[cb++] = (byte)(((Value & 0x0000007F) >> 0) | 0x00);
			}
            return encoded; 
        }
        public static Tag Decode(byte[] encoded, int ofs, int length)
        {
            // создать поток ввода
            using (Stream stream = new MemoryStream(encoded, ofs, length))
            {
                // раскодировать объект
                return Decode(stream); 
            }
        }
        public static Tag Decode(Stream stream)
        {
            // прочитать следующий байт
            int first = stream.ReadByte(); 
            
            // проверить наличие байтов
            if (first < 0) throw new InvalidDataException(); 
        
            // раскодировать объект
            return Decode(stream, (byte)first); 
        }
        public static Tag Decode(Stream stream, byte first) 
        {
            // определить класс объекта 
            TagClass tagClass = TagClass.Universal; int value = 0; 

            // определить класс объекта 
		    switch (first >> 6)
		    {
		    // определить класс объекта 
		    case 0x01: tagClass = TagClass.Application;	break;
		    case 0x02: tagClass = TagClass.Context;		break;
		    case 0x03: tagClass = TagClass.Private;		break;
		    }
		    // извлечь тип объекта
		    if ((first & 0x1F) < 0x1F) value = first & 0x1F; 
		    else {
                // прочитать следующий байт
                int next = stream.ReadByte(); 
                
                // проверить наличие байтов
                if (next < 0) throw new InvalidDataException(); 

			    // для всех непоследних байтов типа
			    while ((next & 0x80) == 0x80)
			    {
				    // скорректировать значение типа
				    value <<= 7; value |= (next & 0x7F);

                    // прочитать следующий байт
                    next = stream.ReadByte(); 
                    
                    // проверить наличие байтов
                    if (next < 0) throw new InvalidDataException(); 
			    }
			    // учесть последний байт типа
			    value <<= 7; value |= next & 0xFF;    
		    }
            // вернуть раскодированный объект
            return new Tag(tagClass, value); 
        }
	}
}
