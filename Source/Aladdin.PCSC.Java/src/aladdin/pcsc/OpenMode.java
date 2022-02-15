package aladdin.pcsc;

///////////////////////////////////////////////////////////////////////////////
// Тип разделения доступа
///////////////////////////////////////////////////////////////////////////////
public enum OpenMode { DIRECT(0), EXCLUSIVE(1), SHARED(2);

    // конструктор
    private OpenMode(int value) { intValue = value; } 
    
    // получить значение
    public int value () { return intValue; } private final int intValue;
    public int encode()
    {
        switch (intValue)
        {
        // закодировать режим открытия
        case 0: return API.SCARD_SHARE_DIRECT;    
        case 1: return API.SCARD_SHARE_EXCLUSIVE; 
        case 2: return API.SCARD_SHARE_SHARED;    
        }
        return 0; 
    }
}
