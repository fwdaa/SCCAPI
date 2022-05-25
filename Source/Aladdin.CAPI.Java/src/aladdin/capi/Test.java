package aladdin.capi;
import aladdin.*; 
import aladdin.asn1.iso.*;
import java.io.*;
import java.util.*; 

////////////////////////////////////////////////////////////////////////////////
// Окружение для тестирования
////////////////////////////////////////////////////////////////////////////////
public abstract class Test 
{
    ///////////////////////////////////////////////////////////////////////////
    // Консоль тестирования
    ///////////////////////////////////////////////////////////////////////////
    public static void print(String format, Object... values)
    {
        // вывести строку
        System.out.print(String.format(format, values)); System.out.flush();
    }
    // вывести строку
    public static void println() { System.out.println(); }
    
    // вывести строку
    public static void println(String format, Object... values)
    {
        // вывести строку
        System.out.println(String.format(format, values));
    }
    public static void dump(String name, byte[] buffer)
    {
        // вывести сообщение
        if (buffer != null) dump(name, buffer, 0, buffer.length); 
        else {
            // вывести сообщение
            if (name != null) println("%1$s = ", name); println("<NULL>"); 
        }
    }
    public static void dump(String name, byte[] buffer, int offset, int length)
    {
        // вывести сообщение
        if (name != null) println("%1$s = ", name); 
        
        // создать строковый буфер
        StringBuilder str = new StringBuilder(); 
        
        // обработать пустые данные
        if (length == 0) str.append("<EMPTY>"); 
        
        // для всех байтов 
        else for (int i = 0; i < length; i++)
        {
            // указать разделитель
            if (i != 0 && (i % 16) == 0) str.append("\n"); 

            // получить шестнадцатеричное представление
            str.append(String.format("%1$02X ", buffer[offset + i])); 
        }
        // вывести сообщение
        println(str.toString()); 
    }
    ////////////////////////////////////////////////////////////////////////////
    // Сгенерировать случайные данные
    ////////////////////////////////////////////////////////////////////////////
    protected static void generate(byte[] buffer, int offset, int length) throws Exception
    {
        // указать генератор случайных данных
        try (IRand rand = new aladdin.capi.Rand(null))
        {
            // сгенерировать случайные данные
            rand.generate(buffer, offset, length); 
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Генерация/импорт ключей
    ////////////////////////////////////////////////////////////////////////////
	protected static KeyPair generateKeyPair(Factory factory, SecurityObject scope, IRand rand, 
        Factory trustFactory, SecurityObject trustScope, boolean generate, String keyOID, 
        IParameters parameters, KeyUsage keyUsage, KeyFlags keyFlags) throws Exception
    {
        if (scope instanceof Container && generate)
        {
            // сгенерировать пару ключей
            return ((Container)scope).generateKeyPair( 
                rand, null, keyOID, parameters, keyUsage, keyFlags
            ); 
        }
        else if (scope instanceof Container && !generate)
        {
            // сгенерировать пару ключей
            try (KeyPair keyPair = trustFactory.generateKeyPair(
                trustScope, rand, null, keyOID, parameters, keyUsage, KeyFlags.EXPORTABLE))
            {
                // указать генератор случайных данных
                try (IRand importRand = new aladdin.capi.Rand(null))
                { 
                    // импортировать пару ключей
                    return ((Container)scope).importKeyPair(importRand, 
                        keyPair.publicKey, keyPair.privateKey, keyUsage, keyFlags
                    ); 
                }
            }
        }
        else {
            // сгенерировать пару ключей
            return factory.generateKeyPair(scope, rand, null, 
                keyOID, parameters, keyUsage, keyFlags
            ); 
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Удаление ключей
    ////////////////////////////////////////////////////////////////////////////
	protected static void deleteKeys(SecurityObject scope) throws Exception
    {
        // удалить ключи контейнера
        if (scope instanceof Container) ((Container)scope).deleteKeys();
    }
    ///////////////////////////////////////////////////////////////////////
    // Тест сравнения для алгоритмов хэширования
    ///////////////////////////////////////////////////////////////////////
    protected static void hashTest(Hash hashAlgorithm, Factory factory, 
        SecurityStore scope, AlgorithmIdentifier parameters) throws Exception
    {
        // создать алгоритм
        try (Hash trustAlgorithm = (Hash)factory.createAlgorithm(
            scope, parameters, Hash.class))
        {
            // определить рахмер блока
            int blockSize = trustAlgorithm.blockSize(); 
            
            // указать допустимые размеры
            int[] dataSizes = new int[] { 0, 1, blockSize - 1, blockSize, blockSize + 1 }; 
            
            // указать генератор случайных данных
            try (IRand rand = new aladdin.capi.Rand(null))
            {
                // выполнить тест
                Hash.compatibleTest(rand, hashAlgorithm, trustAlgorithm, dataSizes); 
            }
        }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Тест сравнения для алгоритмов вычисления имитовставки
    ///////////////////////////////////////////////////////////////////////////
    protected static void macTest(Mac macAlgorithm, 
        Factory factory, SecurityStore scope, 
        AlgorithmIdentifier parameters, int[] dataSizes) throws Exception
    {
        // создать алгоритм
        try (Mac trustAlgorithm = (Mac)factory.createAlgorithm(scope, parameters, Mac.class))
        {
            // указать генератор случайных данных
            try (IRand rand = new aladdin.capi.Rand(null))
            {
                // выполнить тест
                Mac.compatibleTest(rand, macAlgorithm, trustAlgorithm, dataSizes); 
            }
        }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Тест сравнения для алгоритмов шифрования
    ///////////////////////////////////////////////////////////////////////////
    protected static void cipherTest(Cipher cipherAlgorithm, 
        PaddingMode padding, Factory factory, SecurityStore scope, 
        AlgorithmIdentifier parameters, int[] dataSizes) throws Exception
    {
        // создать алгоритм
        try (Cipher trustAlgorithm = (Cipher)factory.createAlgorithm(
            scope, parameters, Cipher.class))
        {
            // указать генератор случайных данных
            try (IRand rand = new aladdin.capi.Rand(null))
            {
                // выполнить тест
                Cipher.compatibleTest(rand, 
                    cipherAlgorithm, trustAlgorithm, padding, dataSizes
                ); 
            }
        }
    }
    protected static void cipherTest(Cipher engine, Factory factory, 
        SecurityStore scope, AlgorithmIdentifier parameters) throws Exception
    {
        // указать допустимые размеры
        int[] dataSizes = new int[] { engine.blockSize() }; 
        
        // выполнить тест
        cipherTest(engine, PaddingMode.NONE, factory, scope, parameters, dataSizes); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Тест сравнения для алгоритмов наследования ключа
    ///////////////////////////////////////////////////////////////////////////
    protected static void keyDeriveTest(KeyDerive kdfAlgorithm, 
        Factory factory, SecurityStore scope, 
        AlgorithmIdentifier parameters, byte[] data, int deriveSize) throws Exception
    {
        // создать алгоритм
        try (KeyDerive trustAlgorithm = (KeyDerive)factory.createAlgorithm(
            scope, parameters, KeyDerive.class))
        {
            // указать генератор случайных данных
            try (IRand rand = new aladdin.capi.Rand(null))
            {
                // выполнить тест
                KeyDerive.compatibleTest(rand, 
                    kdfAlgorithm, trustAlgorithm, data, deriveSize
                ); 
            }
        }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Тест совместимости для алгоритмов подписи
    ///////////////////////////////////////////////////////////////////////////
    protected static void signTest(Factory factory, SecurityStore scope, 
        AlgorithmIdentifier hashParameters, AlgorithmIdentifier signHashParameters, 
        AlgorithmIdentifier signParameters, KeyPair keyPair, KeyFlags keyFlags) throws Exception
    {
        // выполнить тест
        int hashSize = signTest(factory, scope,  
            hashParameters, signHashParameters, keyPair, keyFlags
        ); 
        // выполнить тест
        if (hashSize > 0) signTest(factory, scope,
            signParameters, keyPair, keyFlags, hashSize
        ); 
    }
    private static int signTest(Factory factory, SecurityStore scope, 
        AlgorithmIdentifier hashParameters, AlgorithmIdentifier signHashParameters, 
        KeyPair keyPair, KeyFlags keyFlags) throws Exception
    {
        // указать используемый провайдер
        Factory provider = keyPair.privateKey.factory(); byte[] hash; byte[] signature; 
        
        // указать генератор случайных данных
        try (IRand rand = new aladdin.capi.Rand(null))
        {
            // получить алгоритм хэширования
            try (Hash hashAlgorithm = (Hash)provider.createAlgorithm(
                keyPair.privateKey.scope(), hashParameters, Hash.class)) 
            {
                // выделить память для хэш-значения
                hash = new byte[hashAlgorithm.hashSize()]; 
            }
            // получить алгоритм выработки подписи
            try (SignHash signHash = (SignHash)provider.createAlgorithm(
                keyPair.privateKey.scope(), signHashParameters, SignHash.class)) 
            {
                // проверить наличие алгоритма
                if (signHash == null) return 0; 

                // сгенерировать хэш-значение
                rand.generate(hash, 0, hash.length);

                // подписать хэш-значение
                signature = signHash.sign(keyPair.privateKey, rand, hashParameters, hash); 
            }
            // получить алгоритм проверки подписи
            try (VerifyHash verifyHash = (VerifyHash)provider.createAlgorithm(
                keyPair.privateKey.scope(), signHashParameters, VerifyHash.class)) 
            {
                // при поддержке проверки подписи
                if (verifyHash != null)
                {
                    // проверить подпись хэш-значения
                    verifyHash.verify(keyPair.publicKey, hashParameters, hash, signature); print("OK  ");
                }
                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash2 = (VerifyHash)factory.createAlgorithm(
                    scope, signHashParameters, VerifyHash.class))
                {    
                    // проверить подпись хэш-значения
                    verifyHash2.verify(keyPair.publicKey, hashParameters, hash, signature); print("OK  ");

                    // для экспортируемых ключей
                    if (keyFlags.equals(KeyFlags.EXPORTABLE)) 
                    { 
                        // получить алгоритм выработки подписи
                        try (SignHash signHash2 = (SignHash)factory.createAlgorithm(
                            scope, signHashParameters, SignHash.class))
                        {
                            // подписать хэш-значение
                            signature = signHash2.sign(keyPair.privateKey, rand, hashParameters, hash); 
                        }
                        // при поддержке проверки подписи
                        if (verifyHash != null)
                        {
                            // проверить подпись хэш-значения
                            verifyHash.verify(keyPair.publicKey, hashParameters, hash, signature); print("OK  ");
                        }
                    }
                }
            }
        }
        return hash.length; 
    }
    private static void signTest(Factory factory, SecurityStore scope, 
        AlgorithmIdentifier signParameters, KeyPair keyPair, 
        KeyFlags keyFlags, int dataSize) throws Exception
    {
        // указать используемый провайдер
        Factory provider = keyPair.privateKey.factory(); byte[] data; byte[] signature;  
        
        // указать генератор случайных данных
        try (IRand rand = new aladdin.capi.Rand(null))
        {
            // получить алгоритм выработки подписи
            try (SignData signData = (SignData)provider.createAlgorithm(
                keyPair.privateKey.scope(), signParameters, SignData.class))
            {
                // проверить наличие алгоритма
                if (signData == null) return; 

                // сгенерировать данные
                data = new byte[dataSize]; rand.generate(data, 0, dataSize);

                // подписать данные
                signature = signData.sign(keyPair.privateKey, rand, data, 0, data.length); 
            }
            // получить алгоритм проверки подписи
            try (VerifyData verifyData = (VerifyData)provider.createAlgorithm(
                keyPair.privateKey.scope(), signParameters, VerifyData.class))
            {
                // при поддержке проверки подписи
                if (verifyData != null)
                {
                    // проверить подпись данных
                    verifyData.verify(keyPair.publicKey, data, 0, data.length, signature); print("OK  ");
                }
                // получить алгоритм проверки подписи
                try (VerifyData verifyData2 = (VerifyData)factory.createAlgorithm(
                    scope, signParameters, VerifyData.class))
                {
                    // проверить подпись хэш-значения
                    verifyData2.verify(keyPair.publicKey, data, 0, data.length, signature); print("OK  ");

                    // для экспортируемых ключей
                    if (keyFlags.equals(KeyFlags.EXPORTABLE)) 
                    { 
                        // получить алгоритм выработки подписи
                        try (SignData signData2 = (SignData)factory.createAlgorithm(
                            scope, signParameters, SignData.class))
                        {
                            // подписать данные
                            signature = signData2.sign(keyPair.privateKey, rand, data, 0, data.length); 
                        }
                        // при поддержке проверки подписи
                        if (verifyData != null)
                        {
                            // проверить подпись данных
                            verifyData.verify(keyPair.publicKey, data, 0, data.length, signature); print("OK  ");
                        }
                    }
                }
            }
        }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Тест совместимости для алгоритмов ассиметричного шифрования
    ///////////////////////////////////////////////////////////////////////////
    protected static void ciphermentTest(Factory factory, SecurityStore scope, 
        AlgorithmIdentifier parameters, KeyPair keyPair, 
        KeyFlags keyFlags, int maxDataSize, int[] keySizes) throws Exception
    {
        // выполнить тест
        int maxKeySize = ciphermentTest(factory, scope,  
            parameters, keyPair, keyFlags, maxDataSize
        ); 
        // для всех размеров ключей
        for (int keySize : keySizes)
        {
            // проверить допустимсоть размера
            if (keySize > maxKeySize) continue; 
            
            // выполнить тест
            transportKeyTest(factory, scope, parameters, keyPair, keyFlags, keySize); 
        }
    }
    private static int ciphermentTest(Factory factory, SecurityStore scope, 
        AlgorithmIdentifier parameters, KeyPair keyPair, KeyFlags keyFlags, int dataSize) throws Exception
    {
        // указать используемый провайдер
        Factory provider = keyPair.privateKey.factory(); byte[] data; byte[] encrypted; 
        
        // указать генератор случайных данных
        try (IRand rand = new aladdin.capi.Rand(null))
        {
            // получить алгоритм зашифрования
            try (Encipherment encryption = (Encipherment)provider.createAlgorithm(
                keyPair.privateKey.scope(), parameters, Encipherment.class)) 
            {
                // проверить наличие алгоритма
                if (encryption == null) return 0; 

                // сгенерировать случайные данные
                data = new byte[dataSize]; rand.generate(data, 0, dataSize);

                // зашифровать данные
                encrypted = encryption.encrypt(keyPair.publicKey, rand, data); 
            }
            // получить алгоритм расшифрования
            try (Decipherment decryption = (Decipherment)provider.createAlgorithm(
                keyPair.privateKey.scope(), parameters, Decipherment.class))
            {
                // расшифровать данные
                byte[] decrypted = decryption.decrypt(keyPair.privateKey, encrypted);

                // проверить совпадение результата
                if (Arrays.equals(decrypted, data)) print("OK  "); 

                // при ошибке выбросить исключение
                else throw new IllegalArgumentException(); 

                // получить алгоритм зашифрования
                try (Encipherment encryption2 = (Encipherment)factory.createAlgorithm(
                    scope, parameters, Encipherment.class))
                {
                    // зашифровать данные
                    encrypted = encryption2.encrypt(keyPair.publicKey, rand, data); 
                }
                // расшифровать данные
                decrypted = decryption.decrypt(keyPair.privateKey, encrypted);

                // проверить совпадение результата
                if (Arrays.equals(decrypted, data)) print("OK  "); 

                // при ошибке выбросить исключение
                else throw new IllegalArgumentException(); 

                // для экспортируемых ключей
                if (keyFlags.equals(KeyFlags.EXPORTABLE)) 
                {
                    // получить алгоритм расшифрования
                    try (Decipherment decryption2 = (Decipherment)factory.createAlgorithm(
                        scope, parameters, Decipherment.class))
                    {
                        // расшифровать данные
                        decrypted = decryption2.decrypt(keyPair.privateKey, encrypted);

                        // проверить совпадение результата
                        if (Arrays.equals(decrypted, data)) print("OK  "); 

                        // при ошибке выбросить исключение
                        else throw new IllegalArgumentException(); 
                    }
                }
            }
        }
        return data.length; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Тест совместимости для алгоритмов согласования ключа
    ///////////////////////////////////////////////////////////////////////////
    public static void keyAgreementTest(Factory factory, SecurityStore scope, 
        AlgorithmIdentifier keyAgreementParameters, KeyPair keyPair, 
        KeyFlags keyFlags, KeyPair ephemeralKeyPair, int[] keySizes) throws Exception
    {
        // для всех размеров ключей
        for (int keySize : keySizes)
        {
            // выполнить тест
            keyAgreementTest(factory, scope, keyAgreementParameters, 
                keyPair, keyFlags, ephemeralKeyPair, keySize
            ); 
        }
    }
    public static void keyAgreementTest(Factory factory, SecurityStore scope, 
        AlgorithmIdentifier keyAgreementParameters, KeyPair keyPair, 
        KeyFlags keyFlags, KeyPair ephemeralKeyPair, int keySize) throws Exception
    {
        // указать фабрику кодирования ключей
        SecretKeyFactory keyFactory = SecretKeyFactory.GENERIC; 
        
        // указать используемый провайдер
        Factory provider = keyPair.privateKey.factory(); 
        
        // указать генератор случайных данных
        try (IRand rand = new aladdin.capi.Rand(null))
        {
            // получить алгоритм согласования ключа
            try (IKeyAgreement agreement1 = (IKeyAgreement)provider.createAlgorithm(
                keyPair.privateKey.scope(), keyAgreementParameters, IKeyAgreement.class))
            {
                // проверить наличие алгоритма
                if (agreement1 == null) return; 

                // получить алгоритм согласования ключа
                try (IKeyAgreement agreement2 = (IKeyAgreement)factory.createAlgorithm(
                    scope, keyAgreementParameters, IKeyAgreement.class))
                {
                    // сформировать общий ключ
                    try (DeriveData kdfData = agreement1.deriveKey(
                        keyPair.privateKey, ephemeralKeyPair.publicKey, rand, keyFactory, keySize))
                    {
                        // извлечь ключ и случайные данные
                        byte[] key1 = kdfData.key.value(); byte[] random = kdfData.random; 

                        // сформировать общий ключ
                        try (ISecretKey key2 = agreement2.deriveKey(
                            ephemeralKeyPair.privateKey, keyPair.publicKey, random, keyFactory, keySize))
                        {
                            // проверить совпадение результатов
                            if (Arrays.equals(key1, key2.value())) print("OK  ");

                            // при ошибке выбросить исключение
                            else throw new IllegalArgumentException();
                        }
                    }
                    // сформировать общий ключ
                    try (DeriveData kdfData = agreement2.deriveKey(
                        ephemeralKeyPair.privateKey, keyPair.publicKey, rand, keyFactory, keySize))
                    {
                        // извлечь ключ и случайные данные
                        byte[] key1 = kdfData.key.value(); byte[] random = kdfData.random; 

                        // сформировать общий ключ
                        try (ISecretKey key2 = agreement1.deriveKey(
                            keyPair.privateKey, ephemeralKeyPair.publicKey, random, keyFactory, keySize))
                        {
                            // проверить совпадение результатов
                            if (Arrays.equals(key1, key2.value())) print("OK  ");

                            // при ошибке выбросить исключение
                            else throw new IllegalArgumentException();
                        }
                    }
                    // для экспортируемых ключей
                    if (keyFlags.equals(KeyFlags.EXPORTABLE)) 
                    { 
                        // сформировать общий ключ
                        try (DeriveData kdfData = agreement2.deriveKey(
                            keyPair.privateKey, ephemeralKeyPair.publicKey, rand, keyFactory, keySize))
                        {
                            // извлечь ключ и случайные данные
                            byte[] key1 = kdfData.key.value(); byte[] random = kdfData.random; 

                            // сформировать общий ключ
                            try (ISecretKey key2 = agreement2.deriveKey(
                                ephemeralKeyPair.privateKey, keyPair.publicKey, random, keyFactory, keySize))
                            {
                                // проверить совпадение результатов
                                if (Arrays.equals(key1, key2.value())) print("OK  ");

                                // при ошибке выбросить исключение
                                else throw new IllegalArgumentException();
                            }
                        }
                        // сформировать общий ключ
                        try (DeriveData kdfData = agreement2.deriveKey(
                            ephemeralKeyPair.privateKey, keyPair.publicKey, rand, keyFactory, keySize))
                        {
                            // извлечь ключ и случайные данные
                            byte[] key1 = kdfData.key.value(); byte[] random = kdfData.random; 

                            // сформировать общий ключ
                            try (ISecretKey key2 = agreement2.deriveKey(
                                keyPair.privateKey, ephemeralKeyPair.publicKey, random, keyFactory, keySize))
                            {
                                // проверить совпадение результатов
                                if (Arrays.equals(key1, key2.value())) print("OK  ");

                                // при ошибке выбросить исключение
                                else throw new IllegalArgumentException();
                            }
                        }
                    }
                }
            }
        }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Тест совместимости для алгоритмов траспорта ключа
    ///////////////////////////////////////////////////////////////////////////
    public static void transportKeyTest(Factory factory, SecurityStore scope, 
        AlgorithmIdentifier parameters, KeyPair keyPair, 
        KeyFlags keyFlags, int[] keySizes) throws Exception
    {
        // для всех размеров ключей
        for (int keySize : keySizes)
        {
            // выполнить тест
            transportKeyTest(factory, scope, parameters, keyPair, keyFlags, keySize); 
        }
    }
    public static void transportKeyTest(Factory factory, SecurityStore scope, 
        AlgorithmIdentifier parameters, KeyPair keyPair, 
        KeyFlags keyFlags, int keySize) throws Exception
    {
        // указать фабрику кодирования ключей
        SecretKeyFactory keyFactory = SecretKeyFactory.GENERIC; 
        
        // указать используемый провайдер
        Factory provider = keyPair.privateKey.factory(); TransportKeyData transportData; 
        
        // указать генератор случайных данных
        try (IRand rand = new aladdin.capi.Rand(null))
        {
            // сгенерировать ключ
            try (ISecretKey CEK = keyFactory.generate(rand, keySize)) 
            {
                // получить алгоритм зашифрования ключа
                try (TransportKeyWrap keyWrap = (TransportKeyWrap)provider.createAlgorithm(
                    keyPair.privateKey.scope(), parameters, TransportKeyWrap.class))
                {
                    // проверить наличие алгоритма
                    if (keyWrap == null) return; 

                    // зашифровать данные
                    transportData = keyWrap.wrap(parameters, keyPair.publicKey, rand, CEK); 
                }
                // получить алгоритм расшифрования ключа
                try (TransportKeyUnwrap keyUnwrap = (TransportKeyUnwrap)provider.createAlgorithm(
                    keyPair.privateKey.scope(), parameters, TransportKeyUnwrap.class))
                {
                    // расшифровать данные
                    try (ISecretKey decrypted = keyUnwrap.unwrap(
                        keyPair.privateKey, transportData, keyFactory))
                    {
                        // проверить совпадение результата
                        if (Arrays.equals(decrypted.value(), CEK.value())) print("OK  ");

                        // при ошибке выбросить исключение
                        else throw new IllegalArgumentException();             
                    }
                    // получить алгоритм зашифрования ключа
                    try (TransportKeyWrap keyWrap2 = (TransportKeyWrap)
                        factory.createAlgorithm(scope, parameters, TransportKeyWrap.class))
                    {
                        // зашифровать данные
                        transportData = keyWrap2.wrap(parameters, keyPair.publicKey, rand, CEK); 
                    }
                    // расшифровать данные
                    try (ISecretKey decrypted = keyUnwrap.unwrap(
                        keyPair.privateKey, transportData, keyFactory))
                    {
                        // проверить совпадение результата
                        if (Arrays.equals(decrypted.value(), CEK.value())) print("OK  ");

                        // при ошибке выбросить исключение
                        else throw new IllegalArgumentException();             
                    }
                    // для экспортируемых ключей
                    if (keyFlags.equals(KeyFlags.EXPORTABLE))
                    {
                        // получить алгоритм расшифрования ключа
                        try (TransportKeyUnwrap keyUnwrap2 = (TransportKeyUnwrap)
                            factory.createAlgorithm(scope, parameters, TransportKeyUnwrap.class))
                        {
                            // расшифровать данные
                            try (ISecretKey decrypted = keyUnwrap2.unwrap(
                                keyPair.privateKey, transportData, keyFactory))
                            {
                                // проверить совпадение результата
                                if (Arrays.equals(decrypted.value(), CEK.value())) print("OK  ");

                                // при ошибке выбросить исключение
                                else throw new IllegalArgumentException();             
                            }
                        }
                    }
                }
            }
        }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Тест совместимости для алгоритмов траспорта ключа
    ///////////////////////////////////////////////////////////////////////////
    public static void transportAgreementTest(Factory factory, SecurityStore scope, 
        AlgorithmIdentifier parameters, KeyPair keyPair, KeyFlags keyFlags, 
        KeyPair ephemeralKeyPair, int[] keySizes) throws Exception
    {
        // для всех размеров ключей
        for (int keySize : keySizes)
        {
            // выполнить тест
            transportAgreementTest(factory, scope, parameters, 
                keyPair, keyFlags, ephemeralKeyPair, keySize
            ); 
        }
    }
    public static void transportAgreementTest(Factory factory, SecurityStore scope, 
        AlgorithmIdentifier parameters, KeyPair keyPair, KeyFlags keyFlags, 
        KeyPair ephemeralKeyPair, int keySize) throws Exception
    {
        // указать фабрику кодирования ключей
        SecretKeyFactory keyFactory = SecretKeyFactory.GENERIC; 
        
        // указать используемый провайдер
        Factory provider = keyPair.privateKey.factory(); 
        
        // указать генератор случайных данных
        try (IRand rand = new aladdin.capi.Rand(null))
        {
            // сгенерировать случайный ключ
            try (ISecretKey CEK = keyFactory.generate(rand, keySize)) 
            {
                // получить алгоритм зашифрования ключа
                try (ITransportAgreement agreement1 = (ITransportAgreement)provider.createAlgorithm(
                    keyPair.privateKey.scope(), parameters, ITransportAgreement.class))
                {
                    // проверить наличие алгоритма
                    if (agreement1 == null) return; 

                    // получить алгоритм расшифрования ключа
                    try (ITransportAgreement agreement2 = (ITransportAgreement)
                        factory.createAlgorithm(scope, parameters, ITransportAgreement.class))
                    {
                        // зашифровать данные
                        TransportAgreementData agreementData = agreement1.wrap(
                            keyPair.privateKey, keyPair.publicKey, 
                            new IPublicKey[] { ephemeralKeyPair.publicKey }, rand, CEK
                        );  
                        // расшифровать данные
                        try (ISecretKey decrypted = agreement2.unwrap(ephemeralKeyPair.privateKey, 
                            agreementData.publicKey, agreementData.random, 
                            agreementData.encryptedKeys[0], keyFactory))
                        {
                            // проверить совпадение результата
                            if (Arrays.equals(decrypted.value(), CEK.value())) print("OK  ");

                            // при ошибке выбросить исключение
                            else throw new IllegalArgumentException();             
                        }
                        // зашифровать данные
                        agreementData = agreement2.wrap(
                            ephemeralKeyPair.privateKey, ephemeralKeyPair.publicKey, 
                            new IPublicKey[] { keyPair.publicKey },  rand, CEK 
                        ); 
                        // расшифровать данные
                        try (ISecretKey decrypted = agreement1.unwrap(keyPair.privateKey, 
                            agreementData.publicKey, agreementData.random, 
                            agreementData.encryptedKeys[0], keyFactory))
                        {
                            // проверить совпадение результата
                            if (Arrays.equals(decrypted.value(), CEK.value())) print("OK  ");

                            // при ошибке выбросить исключение
                            else throw new IllegalArgumentException();             
                        }
                        // для экспортируемых ключей
                        if (keyFlags.equals(KeyFlags.EXPORTABLE)) 
                        { 
                            // зашифровать данные
                            agreementData = agreement2.wrap(
                                keyPair.privateKey, keyPair.publicKey, 
                                new IPublicKey[] { ephemeralKeyPair.publicKey }, rand, CEK
                            );  
                            // расшифровать данные
                            try (ISecretKey decrypted = agreement2.unwrap(ephemeralKeyPair.privateKey, 
                                agreementData.publicKey, agreementData.random, 
                                agreementData.encryptedKeys[0], keyFactory))
                            {
                                // проверить совпадение результата
                                if (Arrays.equals(decrypted.value(), CEK.value())) print("OK  ");

                                // при ошибке выбросить исключение
                                else throw new IllegalArgumentException();             
                            }
                            // зашифровать данные
                            agreementData = agreement2.wrap(
                                ephemeralKeyPair.privateKey, ephemeralKeyPair.publicKey, 
                                new IPublicKey[] { keyPair.publicKey }, rand, CEK
                            );  
                            // расшифровать данные
                            try (ISecretKey decrypted = agreement2.unwrap(keyPair.privateKey, 
                                agreementData.publicKey, agreementData.random, 
                                agreementData.encryptedKeys[0], keyFactory))
                            {
                                // проверить совпадение результата
                                if (Arrays.equals(decrypted.value(), CEK.value())) print("OK  ");

                                // при ошибке выбросить исключение
                                else throw new IllegalArgumentException();             
                            }
                        }
                    }
                }
            }
        }
    }
}
