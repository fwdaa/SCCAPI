package aladdin.capi;
import aladdin.*; 
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм согласования общего ключа
///////////////////////////////////////////////////////////////////////////
public abstract class KeyAgreement extends RefObject implements IKeyAgreement
{
    // сгенерировать случайные данные
    public abstract byte[] generate(IParameters parameters, IRand rand) throws IOException;
    
    // согласовать общий ключ на стороне отправителя
    @Override public DeriveData deriveKey(IPrivateKey privateKey, 
        IPublicKey publicKey, IRand rand, 
        SecretKeyFactory keyFactory, int keySize) throws IOException
    {
        // сгенерировать случайные данные
        byte[] random = generate(privateKey.parameters(), rand); 
        
        // сгенерировать ключ
        try (ISecretKey key = deriveKey(
            privateKey, publicKey, random, keyFactory, keySize))
        {
            // вернуть сгенерированные данные
            return new DeriveData(key, random); 
        }
    }
 	// согласовать общий ключ на стороне получателя
	@Override public abstract ISecretKey deriveKey(IPrivateKey privateKey, 
        IPublicKey publicKey, byte[] random, 
        SecretKeyFactory keyFactory, int keySize) throws IOException; 
    
    ////////////////////////////////////////////////////////////////////////////
    // Тест известного ответа
    ////////////////////////////////////////////////////////////////////////////
    protected static void knownTest(SecurityObject scope, IKeyAgreement keyAgreement, 
        IPublicKey publicKey1, IPrivateKey privateKey1,
        IPublicKey publicKey2, IPrivateKey privateKey2,  
        byte[][] random, byte[] check) throws Exception
    {
        // указать фабрику кодирования ключей
        SecretKeyFactory keyFactory = SecretKeyFactory.GENERIC; 
        
        // создать ключевую пару
        try (KeyPair rawKeyPair1 = new KeyPair(publicKey1, privateKey1, null))
        {
            // импортировать пару в контейнер
            try (KeyPair keyPair1 = rawKeyPair1.copyTo(null, scope, 
                new KeyUsage(KeyUsage.KEY_AGREEMENT), KeyFlags.NONE))
            {
                // создать эфемерную пару
                try (KeyPair keyPair2 = new KeyPair(publicKey2, privateKey2, null))
                {
                    // создать генератор случайных данных
                    try (IRand rand = new aladdin.capi.rnd.Fixed(random)) 
                    {
                        // сформировать общий ключ
                        try (DeriveData kdfData = keyAgreement.deriveKey(
                            keyPair1.privateKey, keyPair2.publicKey, rand, keyFactory, check.length))
                        {
                            // извлечь ключ и случайные данные
                            byte[] key = kdfData.key.value(); 

                            // проверить совпадение результатов
                            if (!Arrays.equals(key, check)) throw new IllegalArgumentException();
                        }
                    }
                }
            }
        }
    }
}
