using System;
using System.IO;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Закодированное представление объекта
	///////////////////////////////////////////////////////////////////////////
	public class Encodable : IEncodable
	{
        // конструктор
		protected Encodable(IEncodable encodable)
		{
            this.tag     = encodable.Tag;       // тип объекта
            this.pc      = encodable.PC;        // способ кодирования
			this.content = encodable.Content;	// содержимое объекта
			this.encoded = encodable.Encoded;	// закодированное представление
		}
        // конструктор закодирования
        protected Encodable(Tag tag, PC pc)
        {
            this.tag     = tag;                 // тип объекта
            this.pc      = pc;                  // способ кодирования
            this.content = null;				// содержимое объекта
            this.encoded = null;				// закодированное представление
        }
        // конструктор раскодирования
		private Encodable(Tag tag, PC pc, byte[] content, byte[] encoded)
		{
            this.tag     = tag;                 // тип объекта
            this.pc      = pc;                  // способ кодирования
			this.content = content;				// содержимое объекта
			this.encoded = encoded;				// закодированное представление
		}
        private Tag     tag;                    // тип объекта
        private PC      pc;                     // способ кодирования
		private byte[]  content;				// содержимое объекта
		private byte[]	encoded;				// закодированное представление

        // тип и способ кодирования
		public Tag Tag { get { return tag; }}
		public PC  PC  { get { return pc;  }}

        // содержимое объекта
		public byte[] Content { get 
		{ 
            // содержимое объекта
			return (content != null) ? content : content = GetContent(); 	
		}}
        // содержимое объекта
		protected virtual byte[] GetContent()  { return content; }

        // закодированное представление
		public byte[] Encoded  { get 
		{
			// проверить наличие представления
			if (encoded != null) return encoded; 
			
			// создать представление объекта
			return encoded = Encode(tag, pc, Content).Encoded; 	
		}}
		/////////////////////////////////////////////////////////////////////////////
		// Сравнить два объекта
		/////////////////////////////////////////////////////////////////////////////
		public override int GetHashCode()
		{
			// получить хэш-код объекта
			return Encoded[0].GetHashCode(); 
		}
		public override bool Equals(object obj)
		{
			// сравнить два объекта
			return (obj is IEncodable) ? Equals((IEncodable)obj) : false;  
		}
		public bool Equals(IEncodable obj)
		{
			// выполнить тривиальные проверки
			if (obj == null) return false; if ((object)this == (object)obj) return true;  
				
			// сравнить два объекта
			return Arrays.Equals(Encoded, obj.Encoded);  
		}
        /////////////////////////////////////////////////////////////////////////////
        // Проверить отсутствие данных
        /////////////////////////////////////////////////////////////////////////////
        public static bool IsNullOrEmpty(IEncodable encodable)
        {
            // проверить отсутствие данных
            return encodable == null || encodable.Content.Length == 0; 
        }
		/////////////////////////////////////////////////////////////////////////////
		// Закодировать объект
		/////////////////////////////////////////////////////////////////////////////
		public static IEncodable Encode(Tag tag, PC pc, byte[] content)
        {
            // закодировать тип со способом кодирования
            byte[] encodedTagPC = tag.Encode(pc); 

            // определить размер закодированного типа
            int cb = encodedTagPC.Length; int cbLength = 1; 

			 // учесть размер размера содержимого
			if (content.Length >= 0x01000000) cbLength += 4; else 
			if (content.Length >= 0x00010000) cbLength += 3; else 
			if (content.Length >= 0x00000100) cbLength += 2; else 
			if (content.Length >= 0x00000080) cbLength += 1;

			// выделить память для закодирования
			byte[] encoded = new byte[cb + cbLength + content.Length];

            // скопировать тип объекта
            Array.Copy(encodedTagPC, 0, encoded, 0, cb); 

			// для длинного размера
			if (content.Length >= 0x01000000) { encoded[cb++] = 0x84;

				// закодировать размер содержимого
				encoded[cb++] = (byte)((content.Length & 0x7F000000) >> 24);
				encoded[cb++] = (byte)((content.Length & 0x00FF0000) >> 16);
				encoded[cb++] = (byte)((content.Length & 0x0000FF00) >>  8);
				encoded[cb++] = (byte)((content.Length & 0x000000FF) >>  0);
			}
			// для длинного размера
			else if (content.Length >= 0x00010000) { encoded[cb++] = 0x83;

				// закодировать размер содержимого
				encoded[cb++] = (byte)((content.Length & 0x00FF0000) >> 16);
				encoded[cb++] = (byte)((content.Length & 0x0000FF00) >>  8);
				encoded[cb++] = (byte)((content.Length & 0x000000FF) >>  0);
			}
			// для длинного размера
			else if (content.Length >= 0x00000100) { encoded[cb++] = 0x82;

				// закодировать размер содержимого
				encoded[cb++] = (byte)((content.Length & 0x0000FF00) >>  8);
				encoded[cb++] = (byte)((content.Length & 0x000000FF) >>  0);
			}
			// для длинного размера
			else if (content.Length >= 0x00000080) { encoded[cb++] = 0x81;

				// закодировать размер содержимого
				encoded[cb++] = (byte)((content.Length & 0x000000FF) >> 0);
			}
			// закодировать размер содержимого
			else encoded[cb++] = (byte)content.Length; 

            // скопировать содержимое
            Array.Copy(content, 0, encoded, cb, content.Length); 

			// вернуть закодированный объект
			return new Encodable(tag, pc, content, encoded);  
        }
		// раскодировать объект
		public static IEncodable Decode(byte[] encoded)
		{
			// раскодировать объект
			return Decode(encoded, 0, encoded.Length); 
		}
		// раскодировать объект
		public static IEncodable Decode(byte[] encoded, int ofs, int size)
		{
            // создать поток ввода
            using (Stream stream = new MemoryStream(encoded, ofs, size))
            {
                // раскодировать объект
                return Decode(stream); 
            }
		}
        // раскодировать объект
        public static IEncodable Decode(Stream stream)
        {
            // прочитать следующий байт
            int first = stream.ReadByte(); if (first < 0) throw new InvalidDataException();

            // раскодировать объект
            return Decode(stream, (byte)first); 
        }
        // раскодировать объект
        public static IEncodable Decode(Stream stream, byte first)
        {
		    // определить способ кодирования объекта
		    PC pc = ((first & 0x20) != 0) ? PC.Constructed : PC.Primitive; 
        
            // создать буфер для закодированного представления
            using (MemoryStream encodedStream = new MemoryStream())
            { 
                // прочитать тип объекта
                Tag tag = Tag.Decode(stream, first); byte[] encoded = tag.Encode(pc); 
            
                // сохранить представление объекта
                encodedStream.Write(encoded, 0, encoded.Length);
        
                // указать начальные данные
                int length = 0; byte[] content = null; 
        
                // прочитать следующий байт
                int next = stream.ReadByte(); if (next < 0) throw new InvalidDataException();
            
                // при указании размера содержимого
                encodedStream.WriteByte((byte)next); if ((next & 0x80) == 0)
                {
                    // извлечь размер содержимого
                    length = next; content = new byte[length]; if (length != 0)
                    { 
                        // извлечь содержимое объекта
                        if (stream.Read(content, 0, content.Length) < content.Length) 
                        {
                            // при ошибке выбросить исключение
                            throw new InvalidDataException();  
                        }
                        // сохранить содержимое объекта
                        encodedStream.Write(content, 0, content.Length); 
                    }
                }
                else {
                    // определить размер размера содержимого
                    int cbLength = next & 0x7F;
            
                    // проверить корректность размера
                    if (cbLength == 0x7F) throw new InvalidDataException();
                    if (cbLength == 0x00) 
                    {
                        // проверить корректность данных
                        if (pc == ASN1.PC.Primitive) throw new InvalidDataException();
                
                        // создать внутренний буфер
                        using (MemoryStream contentStream = new MemoryStream())
                        { 
                            // раскодировать внутренний объект
                            IEncodable obj = Decode(stream); encoded = obj.Encoded; 

                            // для всех внутренних объектов
                            while (encoded.Length != 2)
                            {
                                // сохранить внутренннее представление
                                contentStream.Write(encoded, 0, encoded.Length);
                    
                                // раскодировать внутренний объект
                                obj = Decode(stream); encoded = obj.Encoded; 
                            }
                            // проверить корректность данных
                            if (encoded[0] != 0 || encoded[1] != 0) 
                            {
                                // при ошибке выбросить исключение
                                throw new InvalidDataException();
                            }
                            // сохранить внутренее представление
                            content = contentStream.ToArray(); 
                        }
                        // сохранить содержимое объекта
                        encodedStream.Write(content, 0, content.Length); 
                        encodedStream.Write(encoded, 0, encoded.Length);
                    }
                    else {
                        // для всех байтов размера содержимого
                        for (int i = 0; i < cbLength; i++)
                        {
                            // прочитать следующий байт
                            next = stream.ReadByte(); 
                        
                            // проверить наличие байтов
                            if (next < 0) throw new InvalidDataException(); 
                    
                            // скорректировать размер содержимого
                            length <<= 8; length |= next & 0xFF; 
                        
                            // сохранить прочитанный байт
                            encodedStream.WriteByte((byte)next); 
                        }
                        // выделить память для содержимого
                        content = new byte[length]; if (length != 0)
                        { 
                            // извлечь содержимое объекта
                            if (stream.Read(content, 0, content.Length) < content.Length) 
                            {
                                // при ошибке выбросить исключение
                                throw new InvalidDataException();  
                            }
                            // сохранить содержимое объекта
                            encodedStream.Write(content, 0, content.Length); 
                        }
                    }
                }
                // создать закодированный объект
                return new Encodable(tag, pc, content, encodedStream.ToArray());
            }
        }
	}
}
