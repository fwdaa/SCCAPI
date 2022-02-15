using System;
using System.IO;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////////
    // Информационный объект смещения (0x54)
    ///////////////////////////////////////////////////////////////////////////////
    public class DataOffset : DataObject
    {
        // смещение данных
        public readonly int Offset; 

        // конструктор закодирования
        public DataOffset(int offset) : base(Authority.ISO7816, Tag.DataOffset)
        {     
            // сохранить переданные параметры
            Offset = offset; 
        
            // проверить корректность смещения
            if (offset < 0 || offset > Int32.MaxValue) throw new ArgumentException(); 
        } 
        // конструктор раскодирования
        public DataOffset(byte[] content) 

            // сохранить переданные параметры
            : base(Authority.ISO7816, Tag.DataOffset, content) 
        {
            // определить начало значимых байтов
            int i = 0; while (i < content.Length && content[i] == 0) i++; 
        
            // проверить величину смещения
            if (content.Length - i > 4) throw new InvalidDataException(); Offset = 0; 
        
            // вычислить значение
            while (i < content.Length) Offset = (Offset << 8) | content[i]; 
        
            // проверить размер
            if (Offset < 0) throw new InvalidDataException(); 
        } 
        // закодировать смещение
        public override byte[] Content { get 
        {
            // закодировать нулевое смещение
            if (Offset == 0) return new byte[0]; 
        
            // при достаточности одного байта
            else if (Offset <= 0x0000FF) { byte[] encoded = new byte[1]; 
        
                // закодировать размер
                encoded[0] = (byte)Offset; return encoded; 
            }
            // при достаточности двух байтов
            else if (Offset <= 0x00FFFF) { byte[] encoded = new byte[2]; 
        
                // закодировать размер
                encoded[0] = (byte)((Offset >> 8) & 0xFF); 
                encoded[1] = (byte)((Offset >> 0) & 0xFF); return encoded; 
            }
            // при достаточности трех байтов
            else if (Offset <= 0xFFFFFF) { byte[] encoded = new byte[3]; 
        
                // закодировать размер
                encoded[0] = (byte)((Offset >> 16) & 0xFF); 
                encoded[1] = (byte)((Offset >>  8) & 0xFF); 
                encoded[2] = (byte)((Offset >>  0) & 0xFF); return encoded; 
            }
            // при достаточности четырех байтов
            else { byte[] encoded = new byte[4]; 
        
                // закодировать размер
                encoded[0] = (byte)((Offset >> 24) & 0xFF); 
                encoded[1] = (byte)((Offset >> 16) & 0xFF); 
                encoded[2] = (byte)((Offset >>  8) & 0xFF); 
                encoded[3] = (byte)((Offset >>  0) & 0xFF); return encoded; 
            }
        }}
    }
}
