using System;
using System.Text;
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
    public class Test
    {
        ///////////////////////////////////////////////////////////////////////////
        // Консоль тестирования
        ///////////////////////////////////////////////////////////////////////////
        public static void Write(string format, params object[] values)
        {
            // вывести строку
            Console.Write(String.Format(format, values)); 
        }
        // вывести строку
        public static void WriteLine() { Console.WriteLine(); }

        // вывести сообщение
        public static void WriteLine(string format, params object[] objs)
        {
            // вывести сообщение
            Console.WriteLine(String.Format(format, objs)); 
        }
        public static void Dump(string name, byte[] buffer)
        {
            // вывести сообщение
            if (buffer != null) Dump(name, buffer, 0, buffer.Length); 
            else {
                // вывести сообщение
                if (name != null) WriteLine("{0} = ", name); WriteLine("<NULL>"); 
            }
        }
        // вывести значение массива
        public static void Dump(string name, byte[] buffer, int offset, int length)
        {
            // вывести сообщение
            if (name != null) WriteLine("{0} = ", name); 

            // создать строковый буфер
            StringBuilder str = new StringBuilder(); 

            // обработать пустые данные
            if (length == 0) str.Append("<EMPTY>"); 

            // для всех байтов 
            else for (int i = 0; i < length; i++)
            {
                // указать разделитель
                if (i != 0 && (i % 16) == 0) str.Append(Environment.NewLine); 

                // получить шестнадцатеричное представление
                str.AppendFormat("{0:X2} ", buffer[offset + i]); 
            }
            // вывести сообщение
            WriteLine(str.ToString()); 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Генератор фиксированных данных
        ///////////////////////////////////////////////////////////////////////////
        [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
        public sealed class Rand : RefObject, IRand
        {
            // список значений и номер теукущего значения
            private byte[][] values; private int index;  

            // конструктор
            public Rand(params byte[][] values)
            { 
                // сохранить переданные параметры
                this.values = values; index = 0; 
            }
            public void Generate(byte[] data, int dataOff, int dataLen) 
            {
		        // сгенерировать случайные данные
		        byte[] buffer = Generate(dataLen); 

                // скопировать данные
                Array.Copy(buffer, 0, data, dataOff, dataLen); 
            }
            public byte[] Generate(int dataLen) 
            {
                // проверить совпадение размеров
                if (index >= values.Length || values[index].Length != dataLen) 
                {
                    // при ошибке выбросить исключение
                    throw new ArgumentException(); 
                }
                // указать случайные данные
                return values[index++]; 
            }
            // описатель окна
            public object Window { get { return null; }}

            public void Dump()
            {
                // для всех случайных данных
                for (int i = 0; i < values.Length; i++)
                {
                    // указать номер случайных данных
                    String name = String.Format("Random{0}", i); 
            
                    // вывести случайные данные
                    Test.Dump(name, values[i]);
                }
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Сгенерировать случайные данные
        ////////////////////////////////////////////////////////////////////////////
        protected static void Generate(byte[] buffer, int offset, int length)
        {
            // указать генератор случайных данных
            using (IRand rand = new CAPI.Rand(null))
            {
                // сгенерировать случайные данные
                rand.Generate(buffer, offset, length); 
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Генерация/импорт ключей
        ////////////////////////////////////////////////////////////////////////////
        protected static KeyPair GenerateKeyPair(Factory factory, SecurityObject scope, 
            IRand rand, Factory trustFactory, SecurityObject trustScope, bool generate, 
            string keyOID, IParameters parameters, KeyUsage keyUsage, KeyFlags keyFlags) 
        {
            if (scope is Container && generate)
            {
                // сгенерировать пару ключей
                return ((Container)scope).GenerateKeyPair(
                    rand, null, keyOID, parameters, keyUsage, keyFlags
                ); 
            }
            else if (scope is Container && !generate)
            {
                // сгенерировать пару ключей
                using (KeyPair keyPair = trustFactory.GenerateKeyPair(
                    trustScope, rand, null, keyOID, 
                    parameters, keyUsage, KeyFlags.Exportable))
                { 
                    // импортировать пару ключей
                    return ((Container)scope).ImportKeyPair(rand, 
                        keyPair.PublicKey, keyPair.PrivateKey, keyUsage, keyFlags
                    ); 
                }
            }
            // сгенерировать пару ключей
            else return factory.GenerateKeyPair( 
                scope, rand, null, keyOID, parameters, keyUsage, keyFlags
            ); 
        }
        ////////////////////////////////////////////////////////////////////////////
        // Удаление ключей
        ////////////////////////////////////////////////////////////////////////////
        protected static void DeleteKeys(SecurityObject scope)
        {
            // удалить сгенерированные ключи
            if (scope is Container) ((Container)scope).DeleteKeys(); 
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тест сравнения для алгоритмов хэширования
        ////////////////////////////////////////////////////////////////////////////
        protected static void HashTest(Hash hashAlgorithm, Factory factory,
            SecurityStore scope, ASN1.ISO.AlgorithmIdentifier parameters)
        {
            // создать алгоритм
            using (Hash trustAlgorithm = factory.CreateAlgorithm<Hash>(scope, parameters))
            { 
                // определить размер блока
                int blockSize = trustAlgorithm.BlockSize; 
           
                // указать допустимые размеры
                int[] dataSizes = new int[] { 0, 1, blockSize - 1, blockSize, blockSize + 1 }; 

                // указать генератор случайных данных
                using (IRand rand = new CAPI.Rand(null))
                { 
                    // выполнить тест 
                    Hash.CompatibleTest(rand, hashAlgorithm, trustAlgorithm, dataSizes); 
                }
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тест сравнения для алгоритмов вычисления имитовставки
        ////////////////////////////////////////////////////////////////////////////
        protected static void MacTest(Mac macAlgorithm, Factory factory, SecurityStore scope, 
            ASN1.ISO.AlgorithmIdentifier parameters, int[] dataSizes)
        {
            // создать алгоритм
            using (Mac trustAlgorithm = factory.CreateAlgorithm<Mac>(scope, parameters))
            { 
                // указать генератор случайных данных
                using (IRand rand = new CAPI.Rand(null))
                { 
                    // выполнить тест
                    Mac.CompatibleTest(rand, macAlgorithm, trustAlgorithm, dataSizes); 
                }
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тест сравнения для алгоритмов шифрования
        ////////////////////////////////////////////////////////////////////////////
        protected static void CipherTest(Cipher cipherAlgorithm, PaddingMode padding, Factory factory,
            SecurityStore scope, ASN1.ISO.AlgorithmIdentifier parameters, int[] dataSizes) 
        {
            // создать алгоритм
            using (Cipher trustAlgorithm = factory.CreateAlgorithm<Cipher>(scope, parameters))
            { 
                // указать генератор случайных данных
                using (IRand rand = new CAPI.Rand(null))
                { 
                    // выполнить тест
                    Cipher.CompatibleTest(rand, cipherAlgorithm, trustAlgorithm, padding, dataSizes); 
                }
            }
        }
        protected static void CipherTest(Cipher engine, Factory factory,
            SecurityStore scope, ASN1.ISO.AlgorithmIdentifier parameters) 
        {
            // указать допустимые размеры
            int[] dataSizes = new int[] { engine.BlockSize }; 

            // выполнить тест
            CipherTest(engine, PaddingMode.None, factory, scope, parameters, dataSizes); 
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тест сравнения для алгоритмов наследования ключа
        ////////////////////////////////////////////////////////////////////////////
        protected static void KeyDeriveTest(KeyDerive kdfAlgorithm, 
            Factory factory, SecurityStore scope, 
            ASN1.ISO.AlgorithmIdentifier parameters, byte[] data, int deriveSize)
        {
            // создать алгоритм
            using (KeyDerive trustAlgorithm = factory.CreateAlgorithm<KeyDerive>(scope, parameters))
            {
                // указать генератор случайных данных
                using (IRand rand = new CAPI.Rand(null))
                {
                    // выполнить тест
                    KeyDerive.CompatibleTest(rand, kdfAlgorithm, trustAlgorithm, data, deriveSize); 
                }
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тест совместимсоти для алгоритмов подписи
        ////////////////////////////////////////////////////////////////////////////
        protected static void SignTest(Factory factory, SecurityStore scope, 
            ASN1.ISO.AlgorithmIdentifier hashParameters, ASN1.ISO.AlgorithmIdentifier signHashParameters, 
            ASN1.ISO.AlgorithmIdentifier signParameters, KeyPair keyPair, KeyFlags keyFlags)
        {
            // выполнить тест
            int hashSize = SignTest(factory, scope, hashParameters, 
                signHashParameters, keyPair, keyFlags
            ); 
            // выполнить тест
            if (hashSize > 0) SignTest(factory, scope, 
                signParameters, keyPair, keyFlags, hashSize
            ); 
        }
        private static int SignTest(Factory factory, SecurityStore scope, 
            ASN1.ISO.AlgorithmIdentifier hashParameters, 
            ASN1.ISO.AlgorithmIdentifier signParameters, KeyPair keyPair, KeyFlags keyFlags) 
        {
            // указать используемый провайдер
            Factory provider = keyPair.PrivateKey.Factory; byte[] hash = null; byte[] signature = null; 

            // указать генератор случайных данных
            using (IRand rand = new CAPI.Rand(null))
            {
                // получить алгоритм хэширования
                using (Hash hashAlgorithm = provider.CreateAlgorithm<Hash>(
                    keyPair.PrivateKey.Scope, hashParameters)) 
                {
                    // выделить память для хэш-значения
                    hash = new byte[hashAlgorithm.HashSize]; 
                }
                // получить алгоритм выработки подписи
                using (SignHash signHash = provider.CreateAlgorithm<SignHash>(
                    keyPair.PrivateKey.Scope, signParameters))
                { 
                    // проверить наличие алгоритма
                    if (signHash == null) return 0; 

                    // сгенерировать хэш-значение
                    rand.Generate(hash, 0, hash.Length);

                    // подписать хэш-значение
                    signature = signHash.Sign(keyPair.PrivateKey, rand, hashParameters, hash); 
                }
                // получить алгоритм проверки подписи
                using (VerifyHash verifyHash = provider.CreateAlgorithm<VerifyHash>(
                    keyPair.PrivateKey.Scope, signParameters))
                { 
                    // при поддержке проверки подписи
                    if (verifyHash != null) 
                    {
                        // проверить подпись хэш-значения
                        verifyHash.Verify(keyPair.PublicKey, hashParameters, hash, signature); Write("OK  "); 
                    }
                    // получить алгоритм проверки подписи
                    using (VerifyHash verifyHash2 = factory.CreateAlgorithm<VerifyHash>(scope, signParameters))
                    { 
                        // проверить подпись хэш-значения
                        verifyHash2.Verify(keyPair.PublicKey, hashParameters, hash, signature); Write("OK  "); 

                        // для экспортируемых ключей
                        if (keyFlags == KeyFlags.Exportable) 
                        { 
                            // получить алгоритм выработки подписи
                            using (SignHash signHash2 = factory.CreateAlgorithm<SignHash>(scope, signParameters))
                            { 
                                // подписать хэш-значение
                                signature = signHash2.Sign(keyPair.PrivateKey, rand, hashParameters, hash); 
                            }
                            // при поддержке проверки подписи
                            if (verifyHash != null)
                            { 
                                // проверить подпись хэш-значения 
                                verifyHash.Verify(keyPair.PublicKey, hashParameters, hash, signature); Write("OK  "); 
                            }
                        }
                    }
                }
            }
            return hash.Length; 
        }
        private static void SignTest(Factory factory, SecurityStore scope, 
            ASN1.ISO.AlgorithmIdentifier signParameters, 
            KeyPair keyPair, KeyFlags keyFlags, int dataSize)
        {
            // указать используемый провайдер
            Factory provider = keyPair.PrivateKey.Factory; byte[] data = null; byte[] signature = null;

            // указать генератор случайных данных
            using (IRand rand = new CAPI.Rand(null))
            {
                // получить алгоритм выработки подписи
                using (SignData signData = provider.CreateAlgorithm<SignData>(
                    keyPair.PrivateKey.Scope, signParameters))
                { 
                    // проверить наличие алгоритма
                    if (signData == null) return; 

                    // сгенерировать данные
                    data = new byte[dataSize]; rand.Generate(data, 0, dataSize);

                    // подписать данные
                    signature = signData.Sign(keyPair.PrivateKey, rand, data, 0, data.Length); 
                }
                // получить алгоритм проверки подписи
                using (VerifyData verifyData = provider.CreateAlgorithm<VerifyData>(
                    keyPair.PrivateKey.Scope, signParameters))
                { 
                    // при поддержке проверки подписи
                    if (verifyData != null) 
                    {
                        // проверить подпись данных
                        verifyData.Verify(keyPair.PublicKey, data, 0, data.Length, signature); Write("OK  "); 
                    }
                    // получить алгоритм проверки подписи
                    using (VerifyData verifyData2 = factory.CreateAlgorithm<VerifyData>(scope, signParameters))
                    { 
                        // проверить подпись данных
                        verifyData2.Verify(keyPair.PublicKey, data, 0, data.Length, signature); Write("OK  "); 

                        // для экспортируемых ключей
                        if (keyFlags == KeyFlags.Exportable) 
                        { 
                            // получить алгоритм выработки подписи
                            using (SignData signData2 = factory.CreateAlgorithm<SignData>(scope, signParameters))
                            { 
                                // подписать данные
                                signature = signData2.Sign(keyPair.PrivateKey, rand, data, 0, data.Length); 
                            }
                            // при поддержке проверки подписи
                            if (verifyData != null) 
                            {
                                // проверить подпись данных
                                verifyData.Verify(keyPair.PublicKey, data, 0, data.Length, signature); Write("OK  "); 
                            }
                        }
                    }
                }
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тест совместимости для алгоритмов ассиметричного шифрования
        ////////////////////////////////////////////////////////////////////////////
        protected static void CiphermentTest(Factory factory, SecurityStore scope, 
            ASN1.ISO.AlgorithmIdentifier parameters, KeyPair keyPair, 
            KeyFlags keyFlags, int maxDataSize, int[] keySizes)
        {
            // выполнить тест
            int maxKeySize = CiphermentTest(factory, scope, parameters, keyPair, keyFlags, maxDataSize); 
        
            // для всех размеров ключей
            foreach (int keySize in keySizes)
            {
                // проверить допустимсоть размера
                if (keySize > maxKeySize) continue; 
            
                // выполнить тест
                TransportKeyTest(factory, scope, parameters, keyPair, keyFlags, keySize); 
            }
        }
        private static int CiphermentTest(Factory factory, SecurityStore scope, 
            ASN1.ISO.AlgorithmIdentifier parameters, KeyPair keyPair, KeyFlags keyFlags, int dataSize)
        {
            // указать используемый провайдер
            Factory provider = keyPair.PrivateKey.Factory; byte[] data = null; byte[] encrypted = null; 

            // указать генератор случайных данных
            using (IRand rand = new CAPI.Rand(null))
            {
                // получить алгоритм зашифрования
                using (Encipherment encryption = provider.CreateAlgorithm<Encipherment>(
                    keyPair.PrivateKey.Scope, parameters))
                { 
                    // проверить наличие алгоритма
                    if (encryption == null) return 0; 

                    // сгенерировать случайные данные
                    data = new byte[dataSize]; rand.Generate(data, 0, data.Length);

                    // зашифровать данные
                    encrypted = encryption.Encrypt(keyPair.PublicKey, rand, data); 
                }
                // получить алгоритм расшифрования
                using (Decipherment decryption = provider.CreateAlgorithm<Decipherment>(
                    keyPair.PrivateKey.Scope, parameters))
                { 
                    // расшифровать данные
                    byte[] decrypted = decryption.Decrypt(keyPair.PrivateKey, encrypted);

                    // проверить совпадение результата
                    if (Arrays.Equals(decrypted, data)) Write("OK  "); 
                    
                    // при ошибке выбросить исключение
                    else throw new ArgumentException(); 
                
                    // получить алгоритм зашифрования
                    using (Encipherment encryption2 = factory.CreateAlgorithm<Encipherment>(scope, parameters))
                    { 
                        // зашифровать данные
                        encrypted = encryption2.Encrypt(keyPair.PublicKey, rand, data); 
                    }
                    // расшифровать данные
                    decrypted = decryption.Decrypt(keyPair.PrivateKey, encrypted);

                    // проверить совпадение результата
                    if (Arrays.Equals(decrypted, data)) Write("OK  "); 
                    
                    // при ошибке выбросить исключение
                    else throw new ArgumentException(); 

                    // для экспортируемых ключей
                    if (keyFlags == KeyFlags.Exportable) 
                    {
                        // получить алгоритм расшифрования
                        using (Decipherment decryption2 = factory.CreateAlgorithm<Decipherment>(scope, parameters))
                        { 
                            // расшифровать данные
                            decrypted = decryption2.Decrypt(keyPair.PrivateKey, encrypted);

                            // проверить совпадение результата
                            if (Arrays.Equals(decrypted, data)) Write("OK  "); 
                            
                            // при ошибке выбросить исключение
                            else throw new ArgumentException(); 
                        }
                    }
                }
            }
            return data.Length; 
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тест совместимости для алгоритмов согласования ключа
        ////////////////////////////////////////////////////////////////////////////
        public static void KeyAgreementTest(Factory factory, SecurityStore scope, 
            ASN1.ISO.AlgorithmIdentifier keyAgreementParameters, KeyPair keyPair, 
            KeyFlags keyFlags, KeyPair ephemeralKeyPair, int[] keySizes)
        {
            // для всех размеров ключей
            foreach (int keySize in keySizes)
            {
                // выполнить тест
                KeyAgreementTest(factory, scope, keyAgreementParameters, 
                    keyPair, keyFlags, ephemeralKeyPair, keySize
                ); 
            }
        }
        public static void KeyAgreementTest(Factory factory, SecurityStore scope, 
            ASN1.ISO.AlgorithmIdentifier keyAgreementParameters, KeyPair keyPair, 
            KeyFlags keyFlags, KeyPair ephemeralKeyPair, int keySize)
        {
            // указать фабрику кодирования ключей
            SecretKeyFactory keyFactory = SecretKeyFactory.Generic; 

            // указать используемый провайдер
            Factory provider = keyPair.PrivateKey.Factory;

            // указать генератор случайных данных
            using (IRand rand = new CAPI.Rand(null))
            {
                // получить алгоритм зашифрования ключа
                using (IKeyAgreement agreement1 = 
                    provider.CreateAlgorithm<IKeyAgreement>(
                        keyPair.PrivateKey.Scope, keyAgreementParameters))
                { 
                    // проверить наличие алгоритма
                    if (agreement1 == null) return; 

                    // получить алгоритм расшифрования ключа
                    using (IKeyAgreement agreement2 = 
                        factory.CreateAlgorithm<IKeyAgreement>(
                            scope, keyAgreementParameters)) 
                    {
                        // сформировать общий ключ
                        using (DeriveData kdfData = agreement1.DeriveKey(
                            keyPair.PrivateKey, ephemeralKeyPair.PublicKey, rand, keyFactory, keySize))
                        {
                            // извлечь ключ и случайные данные
                            byte[] key1 = kdfData.Key.Value; byte[] random = kdfData.Random; 

                            // сформировать общий ключ
                            using (ISecretKey key2 = agreement2.DeriveKey(ephemeralKeyPair.PrivateKey, 
                                keyPair.PublicKey, random, keyFactory, keySize))
                            {
                                // проверить совпадение результатов
                                if (Arrays.Equals(key1, key2.Value)) Write("OK  "); 
                            
                                // при ошибке выбросить исключение
                                else throw new ArgumentException();
                            }
                        }
                        // сформировать общий ключ
                        using (DeriveData kdfData = agreement2.DeriveKey(
                            ephemeralKeyPair.PrivateKey, keyPair.PublicKey, rand, keyFactory, keySize))
                        {
                            // извлечь ключ и случайные данные
                            byte[] key1 = kdfData.Key.Value; byte[] random = kdfData.Random; 

                            // сформировать общий ключ
                            using (ISecretKey key2 = agreement1.DeriveKey(keyPair.PrivateKey, 
                                ephemeralKeyPair.PublicKey, random, keyFactory, keySize))
                            {
                                // проверить совпадение результатов
                                if (Arrays.Equals(key1, key2.Value)) Write("OK  "); 
                                
                                // при ошибке выбросить исключение
                                else throw new ArgumentException();
                            }
                        }
                        // для экспортируемых ключей
                        if (keyFlags == KeyFlags.Exportable) 
                        { 
                            // сформировать общий ключ
                            using (DeriveData kdfData = agreement2.DeriveKey(keyPair.PrivateKey, 
                                ephemeralKeyPair.PublicKey, rand, keyFactory, keySize))
                            {
                                // извлечь ключ и случайные данные
                                byte[] key1 = kdfData.Key.Value; byte[] random = kdfData.Random; 

                                // сформировать общий ключ
                                using (ISecretKey key2 = agreement2.DeriveKey(ephemeralKeyPair.PrivateKey, 
                                    keyPair.PublicKey, random, keyFactory, keySize))
                                {
                                    // проверить совпадение результатов
                                    if (Arrays.Equals(key1, key2.Value)) Write("OK  "); 
                                    
                                    // при ошибке выбросить исключение
                                    else throw new ArgumentException();
                                }
                            }
                            // сформировать общий ключ
                            using (DeriveData kdfData = agreement2.DeriveKey(
                                ephemeralKeyPair.PrivateKey, keyPair.PublicKey, rand, keyFactory, keySize))
                            {
                                // извлечь ключ и случайные данные
                                byte[] key1 = kdfData.Key.Value; byte[] random = kdfData.Random; 

                                // сформировать общий ключ
                                using (ISecretKey key2 = agreement2.DeriveKey(keyPair.PrivateKey, 
                                    ephemeralKeyPair.PublicKey, random, keyFactory, keySize))
                                {
                                    // проверить совпадение результатов
                                    if (Arrays.Equals(key1, key2.Value)) Write("OK  "); 
                                    
                                    // при ошибке выбросить исключение
                                    else throw new ArgumentException();
                                }
                            }
                        }
                    }
                }
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тест совместимости для алгоритмов транспорта
        ////////////////////////////////////////////////////////////////////////////
        public static void TransportKeyTest(Factory factory, SecurityStore scope, 
            ASN1.ISO.AlgorithmIdentifier parameters, 
            KeyPair keyPair, KeyFlags keyFlags, int[] keySizes)
        {
            // для всех размеров ключей
            foreach (int keySize in keySizes)
            {
                // выполнить тест
                TransportKeyTest(factory, scope, parameters, keyPair, keyFlags, keySize); 
            }
        }
        public static void TransportKeyTest(Factory factory, SecurityStore scope, 
            ASN1.ISO.AlgorithmIdentifier parameters, KeyPair keyPair, KeyFlags keyFlags, int keySize)
        {
            // указать фабрику кодирования ключей
            SecretKeyFactory keyFactory = SecretKeyFactory.Generic; 

            // указать используемый провайдер
            Factory provider = keyPair.PrivateKey.Factory; TransportKeyData transportData = null; 

            // указать генератор случайных данных
            using (IRand rand = new CAPI.Rand(null))
            {
                // сгенерировать ключ
                using (ISecretKey CEK = keyFactory.Generate(rand, keySize))
                { 
                    // получить алгоритм зашифрования ключа
                    using (TransportKeyWrap keyWrap = provider.CreateAlgorithm<TransportKeyWrap>(
                        keyPair.PrivateKey.Scope, parameters))
                    { 
                        // проверить наличие алгоритма
                        if (keyWrap == null) return; 

                        // зашифровать данные
                        transportData = keyWrap.Wrap(parameters, keyPair.PublicKey, rand, CEK); 
                    }
                    // получить алгоритм расшифрования ключа
                    using (TransportKeyUnwrap keyUnwrap = provider.CreateAlgorithm<TransportKeyUnwrap>(
                        keyPair.PrivateKey.Scope, parameters))
                    { 
                        // расшифровать данные
                        using (ISecretKey decrypted = keyUnwrap.Unwrap(keyPair.PrivateKey, transportData, keyFactory))
                        { 
                            // проверить совпадение результата
                            if (Arrays.Equals(decrypted.Value, CEK.Value)) Write("OK  "); 
                        
                            // при ошибке выбросить исключение
                            else throw new ArgumentException(); 
                        }
                        // получить алгоритм зашифрования ключа
                        using (TransportKeyWrap keyWrap2 = factory.CreateAlgorithm<TransportKeyWrap>(
                            scope, parameters))
                        { 
                            // зашифровать данные
                            transportData = keyWrap2.Wrap(parameters, keyPair.PublicKey, rand, CEK); 
                        }
                        // расшифровать данные
                        using (ISecretKey decrypted = keyUnwrap.Unwrap(keyPair.PrivateKey, transportData, keyFactory))
                        {
                            // проверить совпадение результата
                            if (Arrays.Equals(decrypted.Value, CEK.Value)) Write("OK  "); 
                        
                            // при ошибке выбросить исключение
                            else throw new ArgumentException(); 
                        }
                        // для экспортируемых ключей
                        if (keyFlags == KeyFlags.Exportable)
                        {
                            // получить алгоритм расшифрования ключа
                            using (TransportKeyUnwrap keyUnwrap2 = factory.CreateAlgorithm<TransportKeyUnwrap>(
                                scope, parameters))
                            { 
                                // расшифровать данные
                                using (ISecretKey decrypted = keyUnwrap.Unwrap(keyPair.PrivateKey, transportData, keyFactory))
                                {
                                    // проверить совпадение результата
                                    if (Arrays.Equals(decrypted.Value, CEK.Value)) Write("OK  "); 
                                
                                    // при ошибке выбросить исключение
                                    else throw new ArgumentException(); 
                                }
                            }
                        }
                    }
                }
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тест совместимости для алгоритмов транспорта
        ////////////////////////////////////////////////////////////////////////////
        public static void TransportAgreementTest(Factory factory, SecurityStore scope, 
            ASN1.ISO.AlgorithmIdentifier parameters, KeyPair keyPair, 
            KeyFlags keyFlags, KeyPair ephemeralKeyPair, int[] keySizes)
        {
            // для всех размеров ключей
            foreach (int keySize in keySizes)
            {
                // выполнить тест
                TransportAgreementTest(factory, scope, 
                    parameters, keyPair, keyFlags, ephemeralKeyPair, keySize
                ); 
            }
        }
        public static void TransportAgreementTest(Factory factory, SecurityStore scope, 
            ASN1.ISO.AlgorithmIdentifier parameters, KeyPair keyPair, 
            KeyFlags keyFlags, KeyPair ephemeralKeyPair, int keySize) 
        {
            // указать фабрику кодирования ключей
            SecretKeyFactory keyFactory = SecretKeyFactory.Generic; 

            // указать используемый провайдер
            Factory provider = keyPair.PrivateKey.Factory; 

            // указать генератор случайных данных
            using (IRand rand = new CAPI.Rand(null))
            {
                // сгенерировать случайный ключ
                using (ISecretKey CEK = keyFactory.Generate(rand, keySize))
                { 
                    // получить алгоритм зашифрования ключа
                    using (ITransportAgreement agreement1 = provider.CreateAlgorithm<ITransportAgreement>(
                        keyPair.PrivateKey.Scope, parameters))
                    { 
                        // проверить наличие алгоритма
                        if (agreement1 == null) return; 

                        // получить алгоритм расшифрования ключа
                        using (ITransportAgreement agreement2 = factory.
                            CreateAlgorithm<ITransportAgreement>(scope, parameters)) 
                        {
                            // зашифровать данные
                            TransportAgreementData agreementData = agreement1.Wrap(
                                keyPair.PrivateKey, keyPair.PublicKey, 
                                new IPublicKey[] { ephemeralKeyPair.PublicKey }, rand, CEK
                            );  
                            // расшифровать данные
                            using (ISecretKey decrypted = agreement2.Unwrap(ephemeralKeyPair.PrivateKey, 
                                agreementData.PublicKey, agreementData.Random, 
                                agreementData.EncryptedKeys[0], keyFactory))
                            {
                                // проверить совпадение результата
                                if (Arrays.Equals(decrypted.Value, CEK.Value)) Write("OK  "); 
                                    
                                // при ошибке выбросить исключение
                                else throw new ArgumentException(); 
                            }
                            // зашифровать данные
                            agreementData = agreement2.Wrap(
                                ephemeralKeyPair.PrivateKey, ephemeralKeyPair.PublicKey, 
                                new IPublicKey[] { keyPair.PublicKey },  rand, CEK 
                            ); 
                            // расшифровать данные
                            using (ISecretKey decrypted = agreement1.Unwrap(keyPair.PrivateKey, 
                                agreementData.PublicKey, agreementData.Random, 
                                agreementData.EncryptedKeys[0], keyFactory))
                            {
                                // проверить совпадение результата
                                if (Arrays.Equals(decrypted.Value, CEK.Value)) Write("OK  "); 
                                    
                                // при ошибке выбросить исключение
                                else throw new ArgumentException(); 
                            }
                            // для экспортируемых ключей
                            if (keyFlags == KeyFlags.Exportable)
                            { 
                                // зашифровать данные
                                agreementData = agreement2.Wrap(
                                    keyPair.PrivateKey, keyPair.PublicKey, 
                                    new IPublicKey[] { ephemeralKeyPair.PublicKey }, rand, CEK
                                );  
                                // расшифровать данные
                                using (ISecretKey decrypted = agreement2.Unwrap(ephemeralKeyPair.PrivateKey, 
                                    agreementData.PublicKey, agreementData.Random, 
                                    agreementData.EncryptedKeys[0], keyFactory))
                                {
                                    // проверить совпадение результата
                                    if (Arrays.Equals(decrypted.Value, CEK.Value)) Write("OK  "); 
                                        
                                    // при ошибке выбросить исключение
                                    else throw new ArgumentException(); 
                                }
                                // зашифровать данные
                                agreementData = agreement2.Wrap(
                                    ephemeralKeyPair.PrivateKey, ephemeralKeyPair.PublicKey, 
                                    new IPublicKey[] { keyPair.PublicKey }, rand, CEK
                                );  
                                // расшифровать данные
                                using (ISecretKey decrypted = agreement2.Unwrap(keyPair.PrivateKey, 
                                    agreementData.PublicKey, agreementData.Random, 
                                    agreementData.EncryptedKeys[0], keyFactory))
                                {
                                    // проверить совпадение результата
                                    if (Arrays.Equals(decrypted.Value, CEK.Value)) Write("OK  "); 
                                        
                                    // при ошибке выбросить исключение
                                    else throw new ArgumentException(); 
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
