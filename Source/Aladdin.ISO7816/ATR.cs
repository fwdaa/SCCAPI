using System;
using System.IO;

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////
    // ATR смарт-карты
    ///////////////////////////////////////////////////////////////////////////
    public class ATR
    {
        // закодированное представление и исторические байты
        public readonly byte[] Encoded; public readonly HistoricalBytes HistoricalBytes;

        // конструктор
        public ATR(byte[] encoded) 
        {
            // проверить корректность данных
            if (2 > encoded.Length || encoded.Length > 33) 
            {
                // при ошибке выбросить исключение
                throw new InvalidDataException();  
            }
            // проверить корректность данных
            if ((encoded[0] & 0x3B) != 0x3B) throw new InvalidDataException();

            // сохранить переданные параметры 
            int offset = 1; int cb = encoded[offset] & 0x0F; Encoded = encoded;  

            // для всех последовательностей TA, TB, TC, TD
            for (int Y = encoded[offset++] & 0xF0; ; Y = encoded[offset++] & 0xF0)
            {
                // проверить наличие байтов TA, TB, TC и TD
                if ((Y & 0x10) != 0) offset++; if ((Y & 0x20) != 0) offset++;
                if ((Y & 0x40) != 0) offset++; if ((Y & 0x80) != 0) 
                {
                    // проверить корректность размера
                    if (encoded.Length <= offset) throw new InvalidDataException();
                }
                else {
                    // проверить корректность размера
                    if (encoded.Length < offset + cb) throw new InvalidDataException(); break; 
                }
            }
            // сохранить извлеченные объекты
            HistoricalBytes = new HistoricalBytes(encoded, offset, cb);  
        }
    }
}
