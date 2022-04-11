using System;
using System.IO;
using System.Collections.Generic;
using System.Text;

namespace Aladdin.CAPI.GOST.Cipher
{
    ///////////////////////////////////////////////////////////////////////////////
    // Алгоритм ГОСТ R34.12 с добавлением OMAC
    ///////////////////////////////////////////////////////////////////////////////
    public class GOSTR3412_OMAC : CAPI.Cipher
    {
        // создать алгоритм
        public static CAPI.Cipher Create(CAPI.Factory factory, 
            SecurityStore scope, int blockSize, CAPI.Cipher mode, byte[] seed) 
        {
            // закодировать параметры алгоритма HMAC
            ASN1.ISO.AlgorithmIdentifier hmacParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_HMAC_256), ASN1.Null.Instance
            );
            // создать алгоритм HMAC
            using (Mac hmac = factory.CreateAlgorithm<Mac>(scope, hmacParameters))
            {
                // проверить наличие алгоритма шифрования блока
                if (hmac == null) return null; 
            
                // создать алгоритм выработки имитовставки
                using (Mac omac = GOSTR3412.CreateOMAC(factory, scope, blockSize))
                {
                    // обьединить имитовставку с режимом
                    return new GOSTR3412_OMAC(mode, omac, hmac, seed); 
                }
            }
        }
        // алгоритм шифрования и алгоритм вычисления имитовставки
        private CAPI.Cipher cipher; private Mac macAlgorithm;
        // алгоритм HMAC и синхропосылка
        private Mac hmac_gostr3411_2012_256; private byte[] seed;
        
        // конструктор
        public GOSTR3412_OMAC(CAPI.Cipher cipher, 
            Mac macAlgorithm, Mac hmac_gostr3411_2012_256, byte[] seed)
        {
            // проверить размер синхропосылки
            if (seed.Length != 8) throw new ArgumentException(); this.seed = seed; 
        
            // сохранить переданные параметры
            this.cipher = RefObject.AddRef(cipher); 

            // сохранить переданные параметры
            this.macAlgorithm = RefObject.AddRef(macAlgorithm); 
        
            // сохранить переданные параметры
            this.hmac_gostr3411_2012_256 = RefObject.AddRef(hmac_gostr3411_2012_256); 
        }
        // освободить выделенные ресурсы
        protected override void OnDispose() 
        { 
            // освободить выделенные ресурсы
            RefObject.Release(hmac_gostr3411_2012_256); RefObject.Release(macAlgorithm); 

            // освободить выделенные ресурсы
            RefObject.Release(cipher); base.OnDispose();         
        } 
        // алгоритм зашифрования данных
	    public override Transform CreateEncryption(ISecretKey key, PaddingMode padding) 
	    {
            // создать ключи для алгоритмов
            ISecretKey[] keys = CreateKeys(key); 
            try {
                // создать преобразование зашифрования
                using (Transform encryption = cipher.CreateEncryption(keys[0], padding)) 
                {
                    // создать алгоритм вычисления имитовставки
                    using (CAPI.Hash hashAlgorithm = macAlgorithm.ConvertToHash(keys[1]))
                    {
                        // вернуть преобразование зашифрования
                        return new Encryption(encryption, hashAlgorithm); 
                    }
                }
            }
            // освободить выделенные ресурсы
            finally { keys[0].Dispose(); keys[1].Dispose(); }
	    }
	    // алгоритм расшифрования данных
	    public override Transform CreateDecryption(ISecretKey key, PaddingMode padding) 
	    {
            // создать ключи для алгоритмов
            ISecretKey[] keys = CreateKeys(key); 
            try {
                // создать преобразование расшифрования
                using (Transform decryption = cipher.CreateDecryption(keys[0], padding)) 
                {
                    // создать алгоритм вычисления имитовставки
                    using (CAPI.Hash hashAlgorithm = macAlgorithm.ConvertToHash(keys[1]))
                    {
                        // вернуть преобразование расcшифрования
                        return new Decryption(decryption, hashAlgorithm); 
                    }
                }
            }
            // освободить выделенные ресурсы
            finally { keys[0].Dispose(); keys[1].Dispose(); }
	    }
        // создать ключи для алгоритмов
	    protected virtual ISecretKey[] CreateKeys(ISecretKey key) 
        {
            // создать алгоритм наследования ключа
            using (KeyDerive keyDerive = CreateKDF_TREE(Encoding.ASCII.GetBytes("kdf tree"), 1))
            {
                // указать фабрику создания ключей
                SecretKeyFactory keyFactory = SecretKeyFactory.Generic; 
            
                // сгенерировать два ключа
                using (ISecretKey keyPair = keyDerive.DeriveKey(key, seed, keyFactory, key.Length * 2))
                {
                    // проверить наличие значения 
                    byte[] value = keyPair.Value; if (value == null) throw new InvalidKeyException(); 
                
                    // выделить память для значений ключей
                    byte[] key1 = new byte[key.Length]; byte[] key2 = new byte[key.Length];

                    // скопировать значения ключей
                    Array.Copy(value,           0, key1, 0, key1.Length);
                    Array.Copy(value, key1.Length, key2, 0, key2.Length);
                
                    // создать отдельные ключи
                    return new ISecretKey[] { key.KeyFactory.Create(key1), key.KeyFactory.Create(key2) };
                }
            }
        }
        // создать алгоритм наследования
        protected virtual KeyDerive CreateKDF_TREE(byte[] label, int R) 
        { 
            // создать алгоритм наследования
            if (hmac_gostr3411_2012_256 != null) return new CAPI.Derive.TREEKDF(hmac_gostr3411_2012_256, label, R); 
        
            // создать алгоритм хэширования
            using (CAPI.Hash hashAlgorithm = new Hash.GOSTR3411_2012(256))
            {
                // создать алгоритм вычисления имитовставки
                using (Mac macAlgorithm = new CAPI.MAC.HMAC(hashAlgorithm))
                {
                    // создать алгоритм наследования
                    return new CAPI.Derive.TREEKDF(macAlgorithm, label, R); 
                }
            }
        }
        ///////////////////////////////////////////////////////////////////////////
        // Зашифрование данных и выработки имитовставки
        ///////////////////////////////////////////////////////////////////////////
        public class Encryption : TransformCheck
        {
            // конструктор
            public Encryption(Transform encryption, CAPI.Hash hashAlgorithm)
            
                // сохранить переданные параметры
                : base(encryption, hashAlgorithm, true) {} 
            
            // завершить преобразование
            public override int Finish(byte[] data, int dataOff, int dataLen, 
                byte[] buf, int bufOff, byte[] check, int checkOff)
            {
                // определить размер блока и имитовставки
                int blockSize = BlockSize; int checkSize = CheckSize; 
            
                // проверить корректность размера буфера
                if (check.Length < checkOff + CheckSize) throw new IOException(); 
            
                // определить число полных блоков
                int cbBlocks = dataLen / blockSize * blockSize; int cb = 0; 
            
                // обработать полные блоки
                if (cbBlocks > 0) { cb = Update(data, dataOff, cbBlocks, buf, bufOff); 
            
                    // скорректировать смещение
                    dataOff += cbBlocks; dataLen -= cbBlocks; bufOff += cb; 
                }
                // выделить вспомогательный буфер
                byte[] buffer = new byte[dataLen + checkSize]; 
            
                // скопировать последний блок
                Array.Copy(data, dataOff, buffer, 0, dataLen);
            
                // захэшировать данные
                HashAlgorithm.Update(data, dataOff, dataLen);

                // вычислить контрольную сумму
                HashAlgorithm.Finish(buffer, dataLen); 
            
                // зашифровать последний блок и имитовставку
                int cbLast = Transform.Finish(buffer, 0, buffer.Length, buffer, 0); 
            
                // проверить достаточность буфера
                if (buf.Length < bufOff + (cbLast - checkSize)) throw new IOException(); 
            
                // скопировать последний блок
                Array.Copy(buffer, 0, buf, bufOff, cbLast - checkSize);
            
                // скопировать зашифрованную имитовставку
                Array.Copy(buffer, cbLast - checkSize, check, checkOff, checkSize);
            
                // вернуть размер данных
                return cb + (cbLast - checkSize);             
            }
            // завершить преобразование
            public override int Finish(byte[] data, int dataOff, int dataLen, 
                byte[] buf, int bufOff, List<ASN1.ISO.Attribute> attributes)
            {
                // выделить память для контрольной суммы
                byte[] mac = new byte[CheckSize]; String oid = "1.2.643.7.1.0.6.1.1"; 

                // завершить преобразование
                int cb = Finish(data, dataOff, dataLen, buf, bufOff, mac, 0); 
            
                // добавить атрибут
                ASN1.ISO.Attributes.SetAttributeValues(
                    attributes, oid, new ASN1.OctetString(mac)); return cb; 
            }
        }
        ///////////////////////////////////////////////////////////////////////////
        // Расшифрование данных и выработки имитовставки
        ///////////////////////////////////////////////////////////////////////////
        public class Decryption : TransformCheck
        {
            // конструктор
            public Decryption(Transform decryption, CAPI.Hash hashAlgorithm)
            
                // сохранить переданные параметры
                : base(decryption, hashAlgorithm, false) {} 
            
            // завершить преобразование
            public override int Finish(byte[] data, int dataOff, int dataLen, 
                byte[] buf, int bufOff, byte[] check, int checkOff)
            {
                // определить размер блока и имитовставки
                int blockSize = BlockSize; int checkSize = CheckSize; 
            
                // проверить корректность размера буфера
                if (check.Length < checkOff + CheckSize) throw new IOException(); 
            
                // определить число полных блоков
                int cbBlocks = dataLen / blockSize * blockSize; int cb = 0; 
            
                // обработать полные блоки
                if (cbBlocks > 0) { cb = Update(data, dataOff, cbBlocks, buf, bufOff); 
            
                    // скорректировать смещение
                    dataOff += cbBlocks; dataLen -= cbBlocks; bufOff += cb; 
                }
                // выделить вспомогательный буфер
                byte[] buffer = new byte[dataLen + checkSize]; 
            
                // скопировать последний блок
                Array.Copy(data, dataOff, buffer, 0, dataLen);
            
                // скопировать зашифрованную имитовставку
                Array.Copy(check, checkOff, buffer, dataLen, checkSize);
            
                // расшифровать последний блок и имитовставку
                int cbLast = Transform.Finish(buffer, 0, buffer.Length, buffer, 0); 
            
                // захэшировать данные
                HashAlgorithm.Update(buffer, 0, cbLast - checkSize);

                // вычислить контрольную сумму
                byte[] mac = new byte[CheckSize]; HashAlgorithm.Finish(mac, 0); 
            
                // сравнить контрольную сумму
                if (!Arrays.Equals(mac, 0, buffer, cbLast - checkSize, checkSize)) 
                {
                    // при ошибке выбросить исключение
                    throw new InvalidDataException();
                }
                // скопировать последний блок
                Array.Copy(buffer, 0, buf, bufOff, cbLast - checkSize); 
                
                // вернуть размер данных
                return cb + (cbLast - checkSize); 
            }
            // завершить преобразование
            public override int Finish(byte[] data, int dataOff, int dataLen, 
                byte[] buf, int bufOff, List<ASN1.ISO.Attribute> attributes)
            {
                // найти требуемый атрибут
                ASN1.IEncodable encodable = ASN1.ISO.Attributes.GetAttributeValue(
                    attributes, "1.2.643.7.1.0.6.1.1", 0
                ); 
                // проверить наличие атрибута
                if (encodable == null) throw new InvalidDataException(); 
            
                // извлечь значение зашифрованной имтовставки
                byte[] check = new ASN1.OctetString(encodable).Value; 
            
                // завершить преобразование
                return Finish(data, dataOff, dataLen, buf, bufOff, check, 0); 
            }
        }
    }
}
