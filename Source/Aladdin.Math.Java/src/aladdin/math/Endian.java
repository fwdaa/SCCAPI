package aladdin.math;

///////////////////////////////////////////////////////////////////////////
// Способы представления чисел
///////////////////////////////////////////////////////////////////////////
public enum Endian { BIG_ENDIAN(0x0), LITTLE_ENDIAN(0x1), PDP_ENDIAN(0x2); 

    // конструктор
    private Endian(int value) { intValue = value; } private final int intValue;
    
    // получить значение
    public int value() { return intValue; }
}
