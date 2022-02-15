package aladdin.capi;
import aladdin.asn1.iso.*;
import java.security.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Ассиметричный алгоритм зашифрования
///////////////////////////////////////////////////////////////////////////
public abstract class Encipherment extends TransportKeyWrap
{
	// зашифровать данные 
	public abstract byte[] encrypt(IPublicKey key, IRand rand, byte[] data) throws IOException;
    
	// зашифровать ключ
	@Override public TransportKeyData wrap(AlgorithmIdentifier algorithmParameters, 
        IPublicKey publicKey, IRand rand, ISecretKey key) throws IOException, InvalidKeyException
    {
        // проверить тип ключа
        if (key.value() == null) throw new InvalidKeyException(); 
        
        // зашифровать данные
        byte[] encrypted = encrypt(publicKey, rand, key.value()); 
        
        // вернуть зашифрованные данные
        return new TransportKeyData(algorithmParameters, encrypted); 
    }
}
