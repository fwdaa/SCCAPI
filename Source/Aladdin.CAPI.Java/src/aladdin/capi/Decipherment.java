package aladdin.capi;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Ассиметричный алгоритм расшифрования
///////////////////////////////////////////////////////////////////////////
public abstract class Decipherment extends TransportKeyUnwrap
{
	// расшифровать данные
	public abstract byte[] decrypt(IPrivateKey key, byte[] data) throws IOException;
    
	// расшифровать ключ
	@Override public ISecretKey unwrap(IPrivateKey privateKey, 
        TransportKeyData data, SecretKeyFactory keyFactory) throws IOException
    {
        // расшифровать ключ
        byte[] value = decrypt(privateKey, data.encryptedKey); 
        
        // вернуть расшифрованный ключ
        return keyFactory.create(value); 
    }
}
