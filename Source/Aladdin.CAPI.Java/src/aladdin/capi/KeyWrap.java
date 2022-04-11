package aladdin.capi;
import aladdin.*; 
import java.security.*; 
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ключа
///////////////////////////////////////////////////////////////////////////
public abstract class KeyWrap extends RefObject implements IAlgorithm 
{ 
    // тип ключа
    public SecretKeyFactory keyFactory() { return SecretKeyFactory.GENERIC; }
    
	// зашифровать ключ
	public abstract byte[] wrap(IRand rand, ISecretKey key, ISecretKey CEK) 
        throws IOException, InvalidKeyException;

	// расшифровать ключ
	public abstract ISecretKey unwrap(ISecretKey key, byte[] wrappedCEK, 
        SecretKeyFactory keyFactory) throws IOException, InvalidKeyException;
    
    ///////////////////////////////////////////////////////////////////////////
    // Тест известного ответа
    ///////////////////////////////////////////////////////////////////////////
    public static void knownTest(Test.Rand rand, KeyWrap algorithm, 
        byte[] KEK, byte[] CEK, byte[] result) throws Exception
    {
        // указать фабрику кодирования ключей
        SecretKeyFactory keyFactory = SecretKeyFactory.GENERIC; 
        
        // вывести сообщение
        if (rand != null) rand.dump(); 
        
        // указать используемый ключ
        try (ISecretKey k1 = algorithm.keyFactory().create(KEK))
        {
            // вывести сообщение
            Test.dump("KEK", k1.value());
        
            // указать используемый ключ
            try (ISecretKey k2 = keyFactory.create(CEK))
            {
                // вывести сообщение
                Test.dump("CEK", k2.value()); 
                
                // выполнить шифрование ключа
                byte[] wrapped = algorithm.wrap(rand, k1, k2);
            
                // вывести сообщение
                Test.dump("Required", result); Test.dump("Wrapped", wrapped); 

                // сравнить результат
                if (!Arrays.equals(wrapped, result)) throw new IllegalArgumentException(); 
            
                // расшифровать ключ
                try (ISecretKey unwrapped = algorithm.unwrap(k1, wrapped, keyFactory)) 
                {
                    // вывести сообщение
                    Test.dump("Unwrapped", unwrapped.value()); 

                    // сравнить результат
                    if (!Arrays.equals(unwrapped.value(), k2.value())) 
                    {
                        // при ошибке выбросить исключение
                        throw new IllegalArgumentException();
                    }
                    // вывести сообщение
                    Test.println("OK"); Test.println();
                }
            }
        }
    }
}
