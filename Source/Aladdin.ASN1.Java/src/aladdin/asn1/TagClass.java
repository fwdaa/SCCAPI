package aladdin.asn1;

///////////////////////////////////////////////////////////////////////////
// Класс объекта
///////////////////////////////////////////////////////////////////////////
public enum TagClass { UNIVERSAL(0), APPLICATION(1), CONTEXT(2), PRIVATE(3);

    // конструктор
    private TagClass(int value) { intValue = value; } 
    
    // получить значение
    public int value() { return intValue; } private final int intValue;
}
