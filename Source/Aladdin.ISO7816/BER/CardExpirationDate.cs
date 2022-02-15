using System;
using System.Globalization;
using System.IO;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Дата истечения срока действия карты (0x59)
    ///////////////////////////////////////////////////////////////////////////
    public class CardExpirationDate : DataObject
    {
        // дата истечения срока действия карты
        public readonly DateTime Date; 

        // конструктор
        public CardExpirationDate(byte[] content) 
        
            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.CardExpirationDate, content) 
        {
            // раскодировать цифры
            int[] digits = Encoding.DecodeDigits(4, content, 0);

            // извлечь год и месяц
            int yy = digits[0] * 10 + digits[1]; int MM = digits[2] * 10 + digits[3];

            // указать строку форматирования
            string date = String.Format("{0:D2}{1:D2}", yy, MM); 

            // раскодировать дату
            Date = DateTime.ParseExact(date, "yyMM", CultureInfo.CurrentCulture); 
        } 
    }
}
