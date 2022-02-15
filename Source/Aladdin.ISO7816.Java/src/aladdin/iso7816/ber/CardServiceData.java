package aladdin.iso7816.ber;
import aladdin.iso7816.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Данные об услугах, предоставляемых картой (0x43)
///////////////////////////////////////////////////////////////////////////
public class CardServiceData extends DataObject
{
    // конструктор
    public CardServiceData(byte[] content) throws IOException
    {
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.CARD_SERVICE_DATA, content); 
        
        // проверить корректность данных
        if (content.length != 1) throw new IOException(); 
    }
    // значение объекта
    public int data() { return (content()[0] & 0xFF); }
}
