package aladdin.asn1;

///////////////////////////////////////////////////////////////////////////
// Способ кодирования объекта
///////////////////////////////////////////////////////////////////////////
public enum PC { PRIMITIVE(0), CONSTRUCTED(1);

    // конструктор
    private PC(int value) { intValue = value; } 
    
    // получить значение
    public int value() { return intValue; } private final int intValue;
}