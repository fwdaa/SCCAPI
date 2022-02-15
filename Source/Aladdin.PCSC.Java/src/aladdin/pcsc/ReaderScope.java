package aladdin.pcsc;

///////////////////////////////////////////////////////////////////////////////
// Область видимости
///////////////////////////////////////////////////////////////////////////////
public enum ReaderScope { USER(0), RESERVED(1), SYSTEM(2);

    // конструктор
    private ReaderScope(int value) { intValue = value; } 
    
    // получить значение
    public int value () { return intValue; } private final int intValue;
}
