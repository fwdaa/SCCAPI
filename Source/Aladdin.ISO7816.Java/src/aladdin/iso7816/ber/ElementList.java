package aladdin.iso7816.ber;
import aladdin.iso7816.*; 

///////////////////////////////////////////////////////////////////////////
// Список элементов (0x5F 0x41)
///////////////////////////////////////////////////////////////////////////
public class ElementList extends DataObject
{
    // конструктор
    public ElementList(byte[] content) 
    
        // сохранить переданные параметры
        { super(Authority.ISO7816, Tag.ELEMENT_LIST, content); }
}
