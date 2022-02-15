package aladdin.capi;
import aladdin.asn1.iso.pkix.*; 
    
///////////////////////////////////////////////////////////////////////////
// Открытый ключ алгоритма
///////////////////////////////////////////////////////////////////////////
public abstract class PublicKey implements IPublicKey
{  
    // номер версии для сериализации
    private static final long serialVersionUID = -189707757451790760L;

    // фабрика кодирования 
    private final KeyFactory keyFactory; 
    
    // конструктор
    public PublicKey(KeyFactory keyFactory) { this.keyFactory = keyFactory; } 
    
    // идентификатор ключа
    @Override public final String keyOID() { return keyFactory.keyOID(); } 
    
    // параметры ключа
	@Override public abstract IParameters parameters(); 
    
    // фабрика кодирования 
    @Override public final KeyFactory keyFactory() { return keyFactory; }

    // закодированное представление ключа
    @Override public final SubjectPublicKeyInfo encoded() 
    { 
        // закодировать открытый ключ
        return keyFactory().encodePublicKey(this); 
    }
    ////////////////////////////////////////////////////////////////////////////
    // Реализация java.security.PrivateKey
    ////////////////////////////////////////////////////////////////////////////
    
    // идентификатор алгоритма ключа
    @Override public final String getAlgorithm() { return keyOID(); }
    
    // формат закодированного представления
    @Override public final String getFormat() { return "X.509"; }
    
    // закодированное представление
    @Override public final byte[] getEncoded() { return encoded().encoded(); }
}
