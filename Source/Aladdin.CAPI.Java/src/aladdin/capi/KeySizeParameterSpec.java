package aladdin.capi;
import java.security.spec.*;

///////////////////////////////////////////////////////////////////////////////
// Параметры размера ключа в битах
///////////////////////////////////////////////////////////////////////////////
public class KeySizeParameterSpec implements AlgorithmParameterSpec
{
    private static final long serialVersionUID = 7441668315883718329L;
    
    // конструктор
    public KeySizeParameterSpec(int keyBits) { this.keyBits = keyBits; }
    
    // размер ключа в битах
    public int getKeyBits() { return keyBits; } private final int keyBits;  
}
