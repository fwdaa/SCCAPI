package aladdin.capi.gost.cipher;
import aladdin.*;
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.gost.*;
import aladdin.capi.*; 
import aladdin.capi.derive.*;
import aladdin.util.*;
import java.io.*;
import java.security.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////////
// Алгоритм ГОСТ R34.12 с добавлением OMAC
///////////////////////////////////////////////////////////////////////////////
public class GOSTR3412_OMAC extends Cipher
{
    // создать алгоритм
    public static Cipher create(Factory factory, SecurityStore scope, 
        int blockSize, Cipher mode, byte[] seed) throws IOException
    {
        // закодировать параметры алгоритма HMAC
        AlgorithmIdentifier hmacParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOSTR3411_2012_HMAC_256), Null.INSTANCE
        );
        // создать алгоритм HMAC
        try (Mac hmac = (Mac)factory.createAlgorithm(scope, hmacParameters, Mac.class))
        {
            // проверить наличие алгоритма шифрования блока
            if (hmac == null) return null; 
            
            // создать алгоритм выработки имитовставки
            try (Mac omac = GOSTR3412.createOMAC(factory, scope, blockSize, blockSize / 2))
            {
                // обьединить имитовставку с режимом
                return new GOSTR3412_OMAC(mode, omac, hmac, seed); 
            }
        }
    }
    // алгоритм шифрования и алгоритм вычисления имитовставки
    private final Cipher cipher; private final Mac macAlgorithm;
    // алгоритм HMAC и синхропосылка
    private final Mac hmac_gostr3411_2012_256; private final byte[] seed;
        
    // конструктор
    public GOSTR3412_OMAC(Cipher cipher, Mac macAlgorithm, Mac hmac_gostr3411_2012_256, byte[] seed)
    {
        // проверить размер синхропосылки
        if (seed.length != 8) throw new IllegalArgumentException(); this.seed = seed; 
        
        // сохранить переданные параметры
        this.cipher = RefObject.addRef(cipher); 

        // сохранить переданные параметры
        this.macAlgorithm = RefObject.addRef(macAlgorithm); 
        
        // сохранить переданные параметры
        this.hmac_gostr3411_2012_256 = RefObject.addRef(hmac_gostr3411_2012_256); 
    }
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException  
    { 
        // освободить выделенные ресурсы
        RefObject.release(hmac_gostr3411_2012_256); RefObject.release(macAlgorithm); 

        // освободить выделенные ресурсы
        RefObject.release(cipher); super.onClose();         
    } 
    // алгоритм зашифрования данных
	@Override public Transform createEncryption(ISecretKey key, PaddingMode padding) 
        throws IOException, InvalidKeyException
	{
        // создать ключи для алгоритмов
        ISecretKey[] keys = createKeys(key); 
        try {
            // создать преобразование зашифрования
            try (Transform encryption = cipher.createEncryption(keys[0], padding)) 
            {
                // создать алгоритм вычисления имитовставки
                try (Hash hashAlgorithm = macAlgorithm.convertToHash(keys[1]))
                {
                    // вернуть преобразование зашифрования
                    return new Encryption(encryption, hashAlgorithm); 
                }
            }
        }
        // освободить выделенные ресурсы
        finally { keys[0].close(); keys[1].close(); }
	}
	// алгоритм расшифрования данных
	@Override public Transform createDecryption(ISecretKey key, PaddingMode padding) 
        throws IOException, InvalidKeyException 
	{
        // создать ключи для алгоритмов
        ISecretKey[] keys = createKeys(key); 
        try {
            // создать преобразование расшифрования
            try (Transform decryption = cipher.createDecryption(keys[0], padding)) 
            {
                // создать алгоритм вычисления имитовставки
                try (Hash hashAlgorithm = macAlgorithm.convertToHash(keys[1]))
                {
                    // вернуть преобразование расcшифрования
                    return new Decryption(decryption, hashAlgorithm); 
                }
            }
        }
        // освободить выделенные ресурсы
        finally { keys[0].close(); keys[1].close(); }
	}
    // создать ключи для алгоритмов
	protected ISecretKey[] createKeys(ISecretKey key) throws IOException, InvalidKeyException
    {
        // создать алгоритм наследования ключа
        try (KeyDerive keyDerive = createKDF_TREE("kdf tree".getBytes("ASCII"), 1))
        {
            // указать фабрику создания ключей
            SecretKeyFactory keyFactory = SecretKeyFactory.GENERIC; 
            
            // сгенерировать два ключа
            try (ISecretKey keyPair = keyDerive.deriveKey(key, seed, keyFactory, key.length() * 2))
            {
                // проверить наличие значения 
                byte[] value = keyPair.value(); if (value == null) throw new InvalidKeyException(); 
                
                // выделить память для значений ключей
                byte[] key1 = new byte[key.length()]; byte[] key2 = new byte[key.length()];

                // скопировать значения ключей
                System.arraycopy(value,           0, key1, 0, key1.length);
                System.arraycopy(value, key1.length, key2, 0, key2.length);
                
                // создать отдельные ключи
                return new ISecretKey[] { key.keyFactory().create(key1), key.keyFactory().create(key2) };
            }
        }
    }
    // создать алгоритм наследования
    protected KeyDerive createKDF_TREE(byte[] label, int R) throws IOException  
    { 
        // создать алгоритм наследования
        if (hmac_gostr3411_2012_256 != null) return new TREEKDF(hmac_gostr3411_2012_256, label, R); 
        
        // создать алгоритм хэширования
        try (Hash hashAlgorithm = new aladdin.capi.gost.hash.GOSTR3411_2012(256))
        {
            // создать алгоритм вычисления имитовставки
            try (Mac macAlgorithm = new aladdin.capi.mac.HMAC(hashAlgorithm))
            {
                // создать алгоритм наследования
                return new TREEKDF(macAlgorithm, label, R); 
            }
        }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Зашифрование данных и выработки имитовставки
    ///////////////////////////////////////////////////////////////////////////
    public static class Encryption extends TransformCheck
    {
        // конструктор
        public Encryption(Transform encryption, Hash hashAlgorithm)
        {
            // сохранить переданные параметры
            super(encryption, hashAlgorithm, true); 
        }
        // завершить преобразование
        @Override public int finish(byte[] data, int dataOff, int dataLen, 
            byte[] buf, int bufOff, byte[] check, int checkOff) throws IOException
        {
            // определить размер блока и имитовставки
            int blockSize = blockSize(); int checkSize = checkSize(); 
            
            // проверить корректность размера буфера
            if (check.length < checkOff + checkSize) throw new IOException(); 
            
            // определить число полных блоков
            int cbBlocks = dataLen / blockSize * blockSize; int cb = 0; 
            
            // обработать полные блоки
            if (cbBlocks > 0) { cb = update(data, dataOff, cbBlocks, buf, bufOff); 
            
                // скорректировать смещение
                dataOff += cbBlocks; dataLen -= cbBlocks; bufOff += cb; 
            }
            // выделить вспомогательный буфер
            byte[] buffer = new byte[dataLen + checkSize]; 
            
            // скопировать последний блок
            System.arraycopy(data, dataOff, buffer, 0, dataLen);
            
            // захэшировать данные
            hashAlgorithm().update(data, dataOff, dataLen);

            // вычислить контрольную сумму
            hashAlgorithm().finish(buffer, dataLen); 
            
            // зашифровать последний блок и имитовставку
            int cbLast = transform().finish(buffer, 0, buffer.length, buffer, 0); 
            
            // проверить достаточность буфера
            if (buf.length < bufOff + (cbLast - checkSize)) throw new IOException(); 
            
            // скопировать последний блок
            System.arraycopy(buffer, 0, buf, bufOff, cbLast - checkSize);
            
            // скопировать зашифрованную имитовставку
            System.arraycopy(buffer, cbLast - checkSize, check, checkOff, checkSize);
            
            // вернуть размер данных
            return cb + (cbLast - checkSize); 
        }
        // завершить преобразование
        @Override public int finish(byte[] data, int dataOff, int dataLen, byte[] buf, 
            int bufOff, List<Attribute> attributes) throws IOException
        {
            // выделить память для контрольной суммы
            byte[] mac = new byte[checkSize()]; String oid = "1.2.643.7.1.0.6.1.1"; 

            // завершить преобразование
            int cb = finish(data, dataOff, dataLen, buf, bufOff, mac, 0); 
            
            // добавить атрибут
            Attributes.setAttributeValues(attributes, oid, new OctetString(mac)); return cb; 
        }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Расшифрование данных и выработки имитовставки
    ///////////////////////////////////////////////////////////////////////////
    public static class Decryption extends TransformCheck
    {
        // конструктор
        public Decryption(Transform decryption, Hash hashAlgorithm)
        {
            // сохранить переданные параметры
            super(decryption, hashAlgorithm, false); 
        }
        // завершить преобразование
        @Override public int finish(byte[] data, int dataOff, int dataLen, 
            byte[] buf, int bufOff, byte[] check, int checkOff) throws IOException
        {
            // определить размер блока и имитовставки
            int blockSize = blockSize(); int checkSize = checkSize(); 
            
            // проверить корректность размера буфера
            if (check.length < checkOff + checkSize) throw new IOException(); 
            
            // определить число полных блоков
            int cbBlocks = dataLen / blockSize * blockSize; int cb = 0; 
            
            // обработать полные блоки
            if (cbBlocks > 0) { cb = update(data, dataOff, cbBlocks, buf, bufOff); 
            
                // скорректировать смещение
                dataOff += cbBlocks; dataLen -= cbBlocks; bufOff += cb; 
            }
            // выделить вспомогательный буфер
            byte[] buffer = new byte[dataLen + checkSize]; 
            
            // скопировать последний блок
            System.arraycopy(data, dataOff, buffer, 0, dataLen);
            
            // скопировать зашифрованную имитовставку
            System.arraycopy(check, checkOff, buffer, dataLen, checkSize);
            
            // расшифровать последний блок и имитовставку
            int cbLast = transform().finish(buffer, 0, buffer.length, buffer, 0); 
            
            // захэшировать данные
            hashAlgorithm().update(buffer, 0, cbLast - checkSize);

            // вычислить контрольную сумму
            byte[] mac = new byte[checkSize()]; hashAlgorithm().finish(mac, 0); 
            
            // сравнить контрольную сумму
            if (!Array.equals(mac, 0, buffer, cbLast - checkSize, checkSize)) throw new IOException(); 
            
            // скопировать последний блок
            System.arraycopy(buffer, 0, buf, bufOff, cbLast - checkSize); return cb + (cbLast - checkSize); 
        }
        // завершить преобразование
        @Override public int finish(byte[] data, int dataOff, int dataLen, byte[] buf, 
            int bufOff, List<Attribute> attributes) throws IOException
        {
            // найти требуемый атрибут
            IEncodable encodable = Attributes.getAttributeValue(
                attributes, "1.2.643.7.1.0.6.1.1", 0
            ); 
            // проверить наличие атрибута
            if (encodable == null) throw new IOException(); 
            
            // извлечь значение зашифрованной имтовставки
            byte[] check = new OctetString(encodable).value(); 
            
            // завершить преобразование
            return finish(data, dataOff, dataLen, buf, bufOff, check, 0); 
        }
    }
}
