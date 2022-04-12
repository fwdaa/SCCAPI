package aladdin.capi.jcp;
import java.security.spec.*;

///////////////////////////////////////////////////////////////////////////////
// Закодированные параметры алгоритма
///////////////////////////////////////////////////////////////////////////////
public final class EncodedParameterSpec implements AlgorithmParameterSpec 
{
    // формат кодирования и закодированное представление 
    private final String format; private final byte[] encoded; private final byte[] iv; 
    
    // конструктор
    public EncodedParameterSpec(byte[] encoded) { this(encoded, null); }
    
    // конструктор
    public EncodedParameterSpec(byte[] encoded, byte[] iv) { this("ASN.1", encoded, iv); }
        
    // конструктор
    public EncodedParameterSpec(String format, byte[] encoded, byte[] iv)
    {
        // сохранить переданные параметры
        this.format = format; this.encoded = encoded; this.iv = iv; 
    }
    // формат кодирования 
    public final String getFormat() { return format; }
    // закодированное представление 
    public final byte[] getEncoded() { return encoded; }
    
    // синхропосылка
    public final byte[] getIV() { return iv; }
}
