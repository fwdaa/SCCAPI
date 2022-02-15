package aladdin.capi.ansi.pkcs11.keyx.dh;
import aladdin.math.*; 
import aladdin.asn1.*;
import aladdin.asn1.ansi.x942.*;
import aladdin.capi.*;
import aladdin.capi.pkcs11.*;
import aladdin.capi.ansi.pkcs11.*;
import aladdin.pkcs11.*;
import aladdin.pkcs11.jni.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Формирование общего ключа Diffie-Hellman
///////////////////////////////////////////////////////////////////////////
public class KeyAgreement extends aladdin.capi.pkcs11.KeyAgreement
{    
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 
    
    // идентификатор алгоритма шифрования ключа
    private final long kdf; private final String keyWrapOID;
    
	// конструктор
	public KeyAgreement(Applet applet) { this(applet, API.CKD_NULL, null); }
    
	// конструктор
	public KeyAgreement(Applet applet, long kdf, String keyWrapOID)
	{ 
		// сохранить переданные параметры
		super(applet); this.kdf = kdf; this.keyWrapOID = keyWrapOID;
    } 
    @Override protected aladdin.capi.KeyAgreement createSoftwareAlgorithm(
         IParameters parameters) throws IOException
    {
        // создать программный алгоритм
        if (kdf == API.CKD_NULL) return new aladdin.capi.ansi.keyx.dh.KeyAgreement(); 
        
        // указать параметры алгоритма хэширования
        Mechanism mechanism = new Mechanism(API.CKM_SHA_1); 
        
        // создать алгоритм хэширования
        try (aladdin.capi.Hash hashAlgorithm = Creator.createHash(
            applet().provider(), applet(), mechanism))
        {
            // проверить наличие алгоритма
            if (hashAlgorithm == null) throw new UnsupportedOperationException(); 
            
            // создать программный алгоритм
            return new aladdin.capi.ansi.keyx.dh.KeyAgreement(hashAlgorithm, keyWrapOID); 
        }
    }
	// параметры алгоритма
	@Override protected Mechanism getParameters(Session sesssion, 
		IPublicKey publicKey, byte[] random, int keySize)
    {
        // скорректировать случайные данные
        if (kdf == API.CKD_NULL) random = null;
        
        // выполнить преобразование ключа
        aladdin.capi.ansi.x942.IPublicKey dhPublicKey = 
            (aladdin.capi.ansi.x942.IPublicKey)publicKey; 
        
        // закодировать значение ключа
        byte[] y = Convert.fromBigInteger(dhPublicKey.getY(), ENDIAN);
        
        // вернуть параметры алгоритма
        return new Mechanism(API.CKM_X9_42_DH_DERIVE, 
            new CK_X9_42_DH1_DERIVE_PARAMS(kdf, random, y)
        ); 
    }
    // сгенерировать случайные данные
    @Override public byte[] generate(IParameters parameters, IRand rand) throws IOException
    {
        // проверить необходимость генерации
        if (kdf == API.CKD_NULL) return null; 
        
        // сгенерировать случайные данные
        byte[] random = new byte[64]; rand.generate(random, 0, 64); return random;   
    }
    // согласовать общий ключ
    @Override
	public ISecretKey deriveKey(IPrivateKey privateKey, 
		IPublicKey publicKey, byte[] random, 
        SecretKeyFactory keyFactory, int keySize) throws IOException
    {
        // обработать отсутствие идентификатора
        if (keyWrapOID == null) return super.deriveKey(privateKey, publicKey, random, keyFactory, keySize); 
        
        // при наличии эфемерного ключа
        if (privateKey.scope() == null && !applet().provider().canImportSessionPair(applet()))
        {
            // вызвать базовую реализацию
            return super.deriveKey(privateKey, publicKey, random, keyFactory, keySize); 
        }
        // закодировать случайные данные
        OctetString partyAInfo = (random != null) ? new OctetString(random) : null; 

        // закодировать размер ключа шифрования ключа
        OctetString suppPubInfo = new OctetString(Convert.fromInt32(keySize * 8, ENDIAN)); 
        
        // выделить память для ключа
        byte[] value = new byte[keySize]; int hashLen = 20; if (keySize <= hashLen)
        {
            // закодировать номер блока
            byte[] counter = Convert.fromInt32(1, ENDIAN);
            
            // закодировать данные для хэширования
            KeySpecificInfo specificInfo = new KeySpecificInfo(
                new ObjectIdentifier(keyWrapOID), new OctetString(counter)
            );
            // закодировать данные для хэширования
            OtherInfo otherInfo = new OtherInfo(specificInfo, partyAInfo, suppPubInfo); 
            
            // выполнить наследование ключа
            return super.deriveKey(privateKey, publicKey, otherInfo.encoded(), keyFactory, keySize); 
        }
        // для каждого блока ключа шифрования ключа
        for (int i = 0; i < (keySize + hashLen - 1) / hashLen; i++)
        {
            // закодировать номер блока
            byte[] counter = Convert.fromInt32(i + 1, ENDIAN);
            
            // закодировать данные для хэширования
            KeySpecificInfo specificInfo = new KeySpecificInfo(
                new ObjectIdentifier(keyWrapOID), new OctetString(counter)
            );
            // закодировать данные для хэширования
            OtherInfo otherInfo = new OtherInfo(specificInfo, partyAInfo, suppPubInfo); 
            
            // выполнить наследование ключа
            try (ISecretKey key = super.deriveKey(privateKey, publicKey, 
                otherInfo.encoded(), SecretKeyFactory.GENERIC, hashLen))
            {
                // проверить наличие значения
                byte[] keyValue = key.value(); if (keyValue == null) 
                {
                    // при ошибке выбросить исключение
                    throw new aladdin.pkcs11.Exception(API.CKR_KEY_UNEXTRACTABLE); 
                }
                // определить размер части ключа
                int size = (keySize >= (i + 1) * hashLen) ? hashLen : (keySize - i * hashLen); 
            
                // скопировать часть ключа
                System.arraycopy(keyValue, 0, value, i * hashLen, size); 
            }
        }
        // вернуть созданный ключ
        return keyFactory.create(value); 
    }
}
