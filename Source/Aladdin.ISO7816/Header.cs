using System;
using System.IO;

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////////
    // Заголовок объекта
    ///////////////////////////////////////////////////////////////////////////////
    public class Header 
    {
        // тип объекта со способом кодирования и его размер
        public readonly Tag Tag; public readonly int Length; private byte[] encoded; 
    
        // раскодировать заголовок
        public static Header Decode(byte[] encoded, int ofs, int size)
        { 
            // раскодировать тип объекта со способом кодирования
            Tag tag = Tag.Decode(encoded, ofs, size); 
        
            // указать начальные данные
            int cb = tag.Encoded.Length; int length = 0; 
            
            // проверить размер буфера
            if (size <= cb) throw new InvalidDataException(); 
            
            // извлечь размер содержимого
            if ((encoded[ofs + cb] & 0x80) == 0) length = encoded[ofs + cb++];
            else {
                // определить размер размера содержимого
                int cbLength = (encoded[ofs + cb++] & 0x7F);

                // проверить корректность размера
                if (cbLength == 0x7F) throw new InvalidDataException();
                
                // проверить размер буфера
                if (size <= cb + cbLength) throw new InvalidDataException(); 
                
                // для всех байтов размера содержимого
                for (int i = 0; i < cbLength; i++)
                {
                    // скорректировать размер содержимого
                    length <<= 8; length |= encoded[ofs + cb++];
                }
            }
            // скопировать закодированное представление
            byte[] buffer = new byte[cb]; Array.Copy(encoded, ofs, buffer, 0, cb);

            // создать закодированный объект
            return new Header(tag, length, buffer);
        }
        // конструктор
        private Header(Tag tag, int length, byte[] encoded)
        {
            // сохранить переданные параметры
            Tag = tag; Length = length; this.encoded = encoded;
        }
        // конструктор
        public Header(Tag tag, int length)
        {
            // сохранить переданные параметры
            Tag = tag; Length = length; this.encoded = null; 
        }
        // конструктор
        public byte[] Encoded { get 
        {
            // проверить наличие представления
            if (encoded != null) return encoded; 

            // определить размер закодированного типа
            int cb = Tag.Encoded.Length; int cbLength = 1; 

			 // учесть размер размера содержимого
			if (Length >= 0x01000000) cbLength += 4; else 
			if (Length >= 0x00010000) cbLength += 3; else 
			if (Length >= 0x00000100) cbLength += 2; else 
			if (Length >= 0x00000080) cbLength += 1;

			// выделить память для закодирования
			encoded = new byte[cb + cbLength];

            // скопировать тип объекта
            Array.Copy(Tag.Encoded, 0, encoded, 0, cb); 

			// для длинного размера
			if (Length >= 0x01000000) { encoded[cb++] = 0x84;

				// закодировать размер содержимого
				encoded[cb++] = (byte)((Length & 0x7F000000) >> 24);
				encoded[cb++] = (byte)((Length & 0x00FF0000) >> 16);
				encoded[cb++] = (byte)((Length & 0x0000FF00) >>  8);
				encoded[cb++] = (byte)((Length & 0x000000FF) >>  0);
			}
			// для длинного размера
			else if (Length >= 0x00010000) { encoded[cb++] = 0x83;

				// закодировать размер содержимого
				encoded[cb++] = (byte)((Length & 0x00FF0000) >> 16);
				encoded[cb++] = (byte)((Length & 0x0000FF00) >>  8);
				encoded[cb++] = (byte)((Length & 0x000000FF) >>  0);
			}
			// для длинного размера
			else if (Length >= 0x00000100) { encoded[cb++] = 0x82;

				// закодировать размер содержимого
				encoded[cb++] = (byte)((Length & 0x0000FF00) >>  8);
				encoded[cb++] = (byte)((Length & 0x000000FF) >>  0);
			}
			// для длинного размера
			else if (Length >= 0x00000080) { encoded[cb++] = 0x81;

				// закодировать размер содержимого
				encoded[cb++] = (byte)((Length & 0x000000FF) >> 0);
			}
			// закодировать размер содержимого
			else encoded[cb++] = (byte)Length; return encoded; 
        }}
        // извлечь требуемые поля из объекта
        public ASN1.IEncodable Apply(ASN1.IEncodable encodable) 
        {
            // получить тип представления
            Tag encodableTag = new Tag(encodable.Tag, encodable.PC); 
            
            // проверить совпадение типа
            if (Tag != encodableTag) return null; 

            // проверить указание размера
            if (Length == 0x00) return encodable; 
            
            // проверить необходимость усечения
            if (encodable.Content.Length <= Length) return encodable;
        
            // проверить возможность усечения
            if (Tag.PC == ASN1.PC.Constructed) throw new InvalidDataException();
        
            // изменить размер содержимого
            byte[] content = encodable.Content; Array.Resize(ref content, Length); 
                
            // закодировать объект
            return ASN1.Encodable.Encode(encodable.Tag, encodable.PC, content); 
        }
    }
}
