using System;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Функциональные возможности карты (0x47)
    ///////////////////////////////////////////////////////////////////////////
    public class CardCapabilities : DataObject
    {
        // конструктор
        public CardCapabilities(byte[] content) 
            
            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.CardCapabilities, content) {}

        // значение объекта
        public byte Data(int number)
        {
            // проверить наличие данных
            if (Content.Length > number) return Content[number];
        
            // вернуть значение
            return (byte)((number == 1) ? 0x01 : 0x00); 
        }
        // способ кодирования данных
        public DataCoding DataCoding(TagScheme tagScheme) 
        { 
            // способ кодирования данных
            return new DataCoding(tagScheme, Data(1)); 
        }
        // признак поддержки сцепления и расширенных размеров
        public bool SupportChaining { get { return (Data(2) & 0x80) != 0; }}
        public bool SupportExtended { get { return (Data(2) & 0x40) != 0; }}
    }
}
