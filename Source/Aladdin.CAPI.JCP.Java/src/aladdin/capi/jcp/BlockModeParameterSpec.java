package aladdin.capi.jcp;
import java.security.spec.*; 

///////////////////////////////////////////////////////////////////////////////
// Параметры режима блочного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
public class BlockModeParameterSpec implements AlgorithmParameterSpec
{
    // параметры блочного алгоритма шифрования и синхропосылка
    private final java.security.AlgorithmParameters cipherParameters; private final byte[] iv; 
    
    // конструктор
    public BlockModeParameterSpec(java.security.AlgorithmParameters cipherParameters, byte[] iv)
    {
        // сохранить переданные параметры
        this.cipherParameters = cipherParameters; this.iv = iv; 
    }
    // параметры блочного алгоритма шифрования 
    public final java.security.AlgorithmParameters cipherParameters() { return cipherParameters; } 
    
    // синхропосылка
    public final byte[] getIV() { return iv; }
}
