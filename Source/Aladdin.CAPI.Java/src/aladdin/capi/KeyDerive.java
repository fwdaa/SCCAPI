package aladdin.capi;
import aladdin.*; 
import java.security.*; 
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа
///////////////////////////////////////////////////////////////////////////
public abstract class KeyDerive extends RefObject implements IAlgorithm 
{ 
    // тип ключа
    public SecretKeyFactory keyFactory() { return SecretKeyFactory.GENERIC; }
    
	// наследовать ключ
	public abstract ISecretKey deriveKey(ISecretKey key, 
        byte[] random, SecretKeyFactory keyFactory, int deriveSize) 
        throws IOException, InvalidKeyException; 
    
    ///////////////////////////////////////////////////////////////////////////
    // Тест известного ответа
    ///////////////////////////////////////////////////////////////////////////
    public static void knownTest(KeyDerive kdfAlgorithm, 
        byte[] keyValue, byte[] data, byte[] check) throws Exception
    {
        // указать фабрику кодирования ключей
        SecretKeyFactory keyFactory = SecretKeyFactory.GENERIC; 
        
        // указать используемый ключ
        try (ISecretKey key = kdfAlgorithm.keyFactory().create(keyValue))
        {
            // вывести сообщение
            Test.dump("Key", key.value()); Test.dump("Data", data); 
        
            // создать ключ для сравнения
            try (ISecretKey checkKey = keyFactory.create(check))
            {
                // вывести сообщение
                Test.dump("Required", checkKey.value()); 
            
                // наследовать ключ
                try (ISecretKey result = kdfAlgorithm.deriveKey(
                    key, data, keyFactory, check.length))
                {
                    // вывести сообщение
                    Test.dump("Result", result.value()); 
            
                    // проверить совпадение
                    if (!Arrays.equals(result.value(), checkKey.value())) 
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
    ///////////////////////////////////////////////////////////////////////////
    // Тест сравнения
    ///////////////////////////////////////////////////////////////////////////
    public static void compatibleTest(IRand rand, 
        KeyDerive kdfAlgorithm, KeyDerive trustAlgorithm, 
        byte[] data, int deriveSize) throws Exception
    {
        // указать фабрику кодирования ключей
        SecretKeyFactory keyFactory = SecretKeyFactory.GENERIC; 
        
        // получить допустимые размеры ключей
        int[] keySizes = kdfAlgorithm.keyFactory().keySizes(); 
        
        // при отсутствии ограничений на размер ключа
        if (keySizes == KeySizes.UNRESTRICTED || keySizes.length > 32)
        {
            // скорректировать допустимые размеры ключей
            keySizes = new int[] { 0, 8, 16, 24, 32, 64 }; 
        }
        // для всех размеров ключей
        for (int keySize : keySizes)
        { 
            // проверить поддержку размера ключа
            if (!KeySizes.contains(kdfAlgorithm.keyFactory().keySizes(), keySize)) continue; 
            
            // сгенерировать ключ 
            try (ISecretKey key = kdfAlgorithm.keyFactory().generate(rand, keySize))
            {
                // вывести сообщение    
                Test.dump("Key", key.value()); Test.dump("Data", data); 

                // наследовать ключ
                try (ISecretKey key1 = kdfAlgorithm.deriveKey(
                    key, data, keyFactory, deriveSize))
                {
                    // наследовать ключ
                    try (ISecretKey key2 = trustAlgorithm.deriveKey(
                        key, data, keyFactory, deriveSize)) 
                    {
                        // вывести сообщение
                        Test.dump("Derived1", key1.value()); 
                        Test.dump("Derived2", key2.value()); 

                        // проверить совпадение ключей
                        if (!Arrays.equals(key1.value(), key2.value())) 
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
}
