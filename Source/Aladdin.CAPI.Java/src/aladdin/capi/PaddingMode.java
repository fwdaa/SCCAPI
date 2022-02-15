package aladdin.capi;

////////////////////////////////////////////////////////////////////////////////
// Режим дополнения
////////////////////////////////////////////////////////////////////////////////
public enum PaddingMode { ANY(-1), NONE(0), ZERO(1), PKCS5(2), ISO(3), CTS(4); 

    // конструктор
    private PaddingMode(int value) { intValue = value; } 
    
    // получить значение
    public int value() { return intValue; } private final int intValue;
}
