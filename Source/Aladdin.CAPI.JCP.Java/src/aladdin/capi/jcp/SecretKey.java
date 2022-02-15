package aladdin.capi.jcp;
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Симметричный ключ
///////////////////////////////////////////////////////////////////////////////
public class SecretKey implements javax.crypto.SecretKey, Closeable
{
    // номер версии при сериализации
    private static final long serialVersionUID = -9150515034562623520L;

    // используемый провайдер и номер слота
	private final Provider provider; private final int slot;
    // используемый ключ
    private final ISecretKey secretKey; 
    
    // конструктор
    public SecretKey(Provider provider, int slot, ISecretKey secretKey)
    {
        // сохранить переданные параметры
        this.provider = provider; this.slot = slot; this.secretKey = secretKey; 
    }
    // освободить выделенные ресурсы
    @Override public void close() { provider.clearObject(slot); }
    
    // алгоритм ключа
    @Override public String getAlgorithm() { return secretKey.getAlgorithm(); }
    // формат ключа 
    @Override public String getFormat() { return secretKey.getFormat(); }
    // закодированное представление
    @Override public byte[] getEncoded() { return secretKey.getEncoded(); }

    // родной личный ключ
    public final ISecretKey get() { return secretKey; }
}
