package aladdin.asn1.gost;

///////////////////////////////////////////////////////////////////////////////
// Режим шифрования
///////////////////////////////////////////////////////////////////////////////
public enum GOST28147CipherMode { CTR(0), CFB(1), CBC(2);

    // конструктор
    private GOST28147CipherMode(int value) { intValue = value; } private final int intValue;
    
    // получить значение
    public int value() { return intValue; }
}
