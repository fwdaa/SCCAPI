package aladdin.iso7816.ber;
import aladdin.iso7816.*; 

///////////////////////////////////////////////////////////////////////////
// Данные эмитента (0x45)
///////////////////////////////////////////////////////////////////////////
public class CardIssuerData extends DataObject
{
    // конструктор
    public CardIssuerData(byte[] content) 
    {        
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.CARD_ISSUER_DATA, content); 
    }
}
