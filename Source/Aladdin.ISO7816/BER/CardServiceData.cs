using System;
using System.IO;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Данные об услугах, предоставляемых картой (0x43)
    ///////////////////////////////////////////////////////////////////////////
    public class CardServiceData : DataObject
    {
        // конструктор
        public CardServiceData(byte[] content) 
            
            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.CardServiceData, content) 
        {
            // проверить корректность данных
            if (content.Length != 1) throw new InvalidDataException(); 
        }
        // значение объекта
        public int Data { get { return Content[0]; }}
    }
}
