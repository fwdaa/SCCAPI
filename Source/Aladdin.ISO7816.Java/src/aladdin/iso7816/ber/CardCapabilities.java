package aladdin.iso7816.ber;
import aladdin.iso7816.*;

///////////////////////////////////////////////////////////////////////////
// Функциональные возможности карты (0x47)
///////////////////////////////////////////////////////////////////////////
public class CardCapabilities extends DataObject
{
    // конструктор
    public CardCapabilities(byte[] content) 
    {        
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.CARD_CAPABILITIES, content); 
    }
    // значение объекта
    public byte data(int number)
    {
        // проверить наличие данных
        if (content().length > number) return content()[number];
        
        // вернуть значение
        return (byte)((number == 1) ? 0x02 : 0x00); 
    }
    // способ кодирования данных
    public DataCoding dataCoding(TagScheme tagScheme) 
    { 
        // способ кодирования данных
        return new DataCoding(tagScheme, data(1)); 
    }
    // признак поддержки сцепления и расширенных размеров
    public boolean supportChaining() { return (data(2) & 0x80) != 0; }
    public boolean supportExtended() { return (data(2) & 0x40) != 0; }
}
