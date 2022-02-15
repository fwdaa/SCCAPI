package aladdin.capi;

///////////////////////////////////////////////////////////////////////////
// Область видимости
///////////////////////////////////////////////////////////////////////////
public enum Scope { ANY(0), SYSTEM(1), USER(2); 

    // конструктор
    private Scope(int value) { intValue = value; } 
    
    // получить значение
    public int value() { return intValue; } private final int intValue;
}
