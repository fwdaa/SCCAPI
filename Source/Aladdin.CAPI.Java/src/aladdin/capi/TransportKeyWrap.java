package aladdin.capi;
import aladdin.*; 
import aladdin.asn1.iso.*; 
import java.security.*; 
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм транспорта ключа на стороне-отправителе
///////////////////////////////////////////////////////////////////////////
public abstract class TransportKeyWrap extends RefObject implements IAlgorithm
{
	// действия стороны-отправителя
	public abstract TransportKeyData wrap(AlgorithmIdentifier algorithmParameters, 
        IPublicKey publicKey, IRand rand, ISecretKey key) throws IOException, InvalidKeyException;
    
    ////////////////////////////////////////////////////////////////////////////
    // Тест известного ответа
    ////////////////////////////////////////////////////////////////////////////
    protected static void knownTest(TransportKeyWrap transportKeyWrap, 
        AlgorithmIdentifier algorithmParameters, IPublicKey publicKey, 
        byte[][] random, byte[] CEK, byte[] check) throws Exception
    {
        // указать фабрику кодирования ключей
        SecretKeyFactory keyFactory = SecretKeyFactory.GENERIC; 
        
        // указать генератор случайных данных
        try (IRand rand = new aladdin.capi.rnd.Fixed(random)) 
        {
            // указать используемый ключ
            try (ISecretKey key = keyFactory.create(CEK))
            {
                // зашифровать данные
                TransportKeyData transportData = transportKeyWrap.wrap(
                    algorithmParameters, publicKey, rand, key
                ); 
                // проверить совпадение результатов
                if (!Arrays.equals(transportData.encryptedKey, check)) 
                {
                    // при ошибке выбросить исключение
                    throw new IllegalArgumentException();             
                }
            }
        }
    }
}
