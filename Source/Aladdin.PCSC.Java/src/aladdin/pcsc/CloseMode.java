package aladdin.pcsc;

///////////////////////////////////////////////////////////////////////////////
// Режим закрытия
///////////////////////////////////////////////////////////////////////////////
public enum CloseMode { LEAVE(0), RESET(1), UNPOWER(2), EJECT(3);

    // конструктор
    private CloseMode(int value) { intValue = value; } 
    
    // получить значение
    public int value () { return intValue; } private final int intValue;
    public int encode()
    {
        switch (intValue)
        {
        // закодировать режим закрытия
        case 0: return API.SCARD_LEAVE_CARD;    
        case 1: return API.SCARD_RESET_CARD; 
        case 2: return API.SCARD_UNPOWER_CARD;    
        case 3: return API.SCARD_EJECT_CARD;    
        }
        return 0; 
    }
}
