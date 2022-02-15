package aladdin.capi.ec;

///////////////////////////////////////////////////////////////////////////////
// Способ кодирования точек на эллиптической кривой
///////////////////////////////////////////////////////////////////////////////
public enum Encoding { DEFAULT(0), COMPRESSED(1), UNCOMPRESSED(2), HYBRID(3); 

    // конструктор
    private Encoding(int value) { intValue = value; } 
  
    // получить значение
    public int value() { return intValue; } private final int intValue;
}
