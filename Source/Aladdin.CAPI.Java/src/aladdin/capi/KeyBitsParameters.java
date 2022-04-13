package aladdin.capi;
import java.security.spec.*;

///////////////////////////////////////////////////////////////////////////////
// Параметры размера ключа в битах
///////////////////////////////////////////////////////////////////////////////
public class KeyBitsParameters implements IKeyBitsParameters
{
    private static final long serialVersionUID = 7441668315883718329L;
    
    // конструктор
    public KeyBitsParameters(int keyBits) { this.keyBits = keyBits; }
    
    // размер ключа в битах
    @Override public int getKeyBits() { return keyBits; } private final int keyBits;  
    
    // получить параметры алгоритма
    @Override public <T extends AlgorithmParameterSpec> 
        T getParameterSpec(Class<T> specType) 
            throws InvalidParameterSpecException
    {
        // операция не поддерживается
        throw new InvalidParameterSpecException(); 
    }
}
