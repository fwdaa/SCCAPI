package aladdin.capi;
import aladdin.*; 
import aladdin.asn1.iso.*; 
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Выработка подписи хэш-значения
///////////////////////////////////////////////////////////////////////////
public abstract class SignHash extends RefObject implements IAlgorithm
{
    // алгоритм подписи хэш-значения
	public abstract byte[] sign(IPrivateKey key, IRand rand, 
		AlgorithmIdentifier hashAgorithm, byte[] hash) throws IOException;
    
    ////////////////////////////////////////////////////////////////////////////
    // Тест известного ответа
    ////////////////////////////////////////////////////////////////////////////
    protected static void knownTest(SecurityObject scope, SignHash signHash, 
        IPublicKey publicKey, IPrivateKey privateKey, byte[][] random, 
        AlgorithmIdentifier hashParameters, byte[] hash, byte[] check) throws Exception
    {
        // создать ключевую пару
        try (KeyPair rawKeyPair = new KeyPair(publicKey, privateKey, null))
        {
            // импортировать пару в контейнер
            try (KeyPair keyPair = rawKeyPair.copyTo(null, scope, 
                new KeyUsage(KeyUsage.DIGITAL_SIGNATURE), KeyFlags.NONE))
            {
                // указать генератор случайных данных
                try (IRand rand = new aladdin.capi.rnd.Fixed(random))
                {
                    // подписать хэш-значение
                    byte[] signature = signHash.sign(keyPair.privateKey, rand, hashParameters, hash); 

                    // проверить совпадение результатов
                    if (!Arrays.equals(signature, check)) throw new IllegalArgumentException();
                }
            }
        }
    }
} 
