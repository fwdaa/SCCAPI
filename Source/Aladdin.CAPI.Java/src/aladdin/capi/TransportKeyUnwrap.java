package aladdin.capi;
import aladdin.*; 
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм транспорта ключа на стороне-получателе
///////////////////////////////////////////////////////////////////////////
public abstract class TransportKeyUnwrap extends RefObject implements IAlgorithm
{
	// действия стороны-получателя
	public abstract ISecretKey unwrap(IPrivateKey privateKey, 
        TransportKeyData data, SecretKeyFactory keyFactory) throws IOException; 
    
    ////////////////////////////////////////////////////////////////////////////
    // Тест известного ответа
    ////////////////////////////////////////////////////////////////////////////
    protected static void knownTest(SecurityObject scope, 
        TransportKeyUnwrap transportKeyUnwrap, IPublicKey publicKey, 
        IPrivateKey privateKey, byte[] CEK, TransportKeyData check) throws Exception
    {
        // указать фабрику кодирования ключей
        SecretKeyFactory keyFactory = SecretKeyFactory.GENERIC; 
        
        // создать ключевую пару
        try (KeyPair rawKeyPair = new KeyPair(publicKey, privateKey, null))
        {
            // импортировать пару в контейнер
            try (KeyPair keyPair = rawKeyPair.copyTo(null, scope, 
                new KeyUsage(KeyUsage.KEY_ENCIPHERMENT), KeyFlags.NONE))
            {
                // расшифровать данные
                try (ISecretKey decrypted = transportKeyUnwrap.unwrap(
                    keyPair.privateKey, check, keyFactory))
                {
                    // проверить совпадение результата
                    if (!Arrays.equals(decrypted.value(), CEK)) throw new IllegalArgumentException();
                }
            }
        }
    }
}
