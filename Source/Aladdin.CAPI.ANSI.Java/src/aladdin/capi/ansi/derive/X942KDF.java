package aladdin.capi.ansi.derive;
import aladdin.*; 
import aladdin.math.*;
import aladdin.asn1.*;
import aladdin.asn1.ansi.x942.*;
import aladdin.capi.*; 
import aladdin.util.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Наследование ключа X.942
///////////////////////////////////////////////////////////////////////////
public class X942KDF extends KeyDerive
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 
    
	// алгоритм хэширования и идентификатор алгоритма шифрования ключа
	private final Hash hashAlgorithm; private final String wrapOID; 

	// конструктор
	public X942KDF(Hash hashAlgorithm, String wrapOID) 
    {
        // сохранить переданные параметры
        this.hashAlgorithm = RefObject.addRef(hashAlgorithm); this.wrapOID = wrapOID;
    }    
    // освободить ресурсы 
    @Override protected void onClose() throws IOException 
    { 
        // освободить ресурсы 
        RefObject.release(hashAlgorithm); super.onClose();            
    }
	// сгенерировать блок данных
	@Override public ISecretKey deriveKey(ISecretKey key, 
        byte[] random, SecretKeyFactory keyFactory, int deriveSize) 
        throws IOException, InvalidKeyException
	{
        // проверить наличие размера
        if (deriveSize < 0) throw new IllegalStateException(); 
        
        // при указании случайных данных
        if (random != null)
        {
            // проверить корректность параметров
            if (wrapOID != null && random.length != 64) throw new IllegalArgumentException(); 
        }
        // проверить корректность ключа
        byte[] ZZ = key.value(); if (ZZ == null) throw new InvalidKeyException(); 
        
        // определить размер хэш-значения
        int hashLen = hashAlgorithm.hashSize(); byte[] KEK = new byte[deriveSize];

        // для каждого блока ключа шифрования ключа
        for (int i = 0; i < (deriveSize + hashLen - 1) / hashLen; i++)
        {
            // закодировать номер блока
            byte[] counter = Convert.fromInt32(i + 1, ENDIAN);
            
            // при указании идентификатора алгоритма
            byte[] KM = ZZ; if (wrapOID != null)
            {
                // закодировать случайные данные
                OctetString partyAInfo = (random != null) ? new OctetString(random) : null; 

                // закодировать размер ключа шифрования ключа
                OctetString suppPubInfo = new OctetString(
                    Convert.fromInt32(deriveSize * 8, ENDIAN)
                ); 
                // закодировать данные для хэширования
                KeySpecificInfo specificInfo = new KeySpecificInfo(
                    new ObjectIdentifier(wrapOID), new OctetString(counter)
                );
                // закодировать данные для хэширования
                OtherInfo otherInfo = new OtherInfo(
                    specificInfo, partyAInfo, suppPubInfo
                ); 
                // закодировать данные для хэширования
                KM = Array.concat(ZZ, otherInfo.encoded());
            }
            // закодировать данные для хэширования
            else if (random != null) KM = Array.concat(ZZ, random);
            
            // захэшировать данные
            byte[] hash = hashAlgorithm.hashData(KM, 0, KM.length); 

            // в зависимости от размера данных
            if (deriveSize >= (i + 1) * hashLen) 
            {
                // скопировать часть ключа
                System.arraycopy(hash, 0, KEK, i * hashLen, hashLen); 
            }
            // скопировать часть ключа
            else System.arraycopy(hash, 0, KEK, i * hashLen, deriveSize - i * hashLen); 
        }
        return keyFactory.create(KEK); 
	}
    ////////////////////////////////////////////////////////////////////////////
    // Тест известного ответа
    ////////////////////////////////////////////////////////////////////////////
    public static void testSHA1(Hash sha1) throws Exception
    {
        // создать алгоритм наследования ключа
        try (KeyDerive kdfAlgorithm = new X942KDF(
            sha1, aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_TDES192_WRAP))
        {
            // выполнить тест
            knownTest(kdfAlgorithm, new byte[] {
                (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, 
                (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, 
                (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, 
                (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f, 
                (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13
            }, null, new byte[] {
                (byte)0xa0, (byte)0x96, (byte)0x61, (byte)0x39, 
                (byte)0x23, (byte)0x76, (byte)0xf7, (byte)0x04, 
                (byte)0x4d, (byte)0x90, (byte)0x52, (byte)0xa3, 
                (byte)0x97, (byte)0x88, (byte)0x32, (byte)0x46, 
                (byte)0xb6, (byte)0x7f, (byte)0x5f, (byte)0x1e, 
                (byte)0xf6, (byte)0x3e, (byte)0xb5, (byte)0xfb            
            });
        }
        // создать алгоритм наследования ключа
        try (KeyDerive kdfAlgorithm = new X942KDF(
            sha1, aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_RC2_128_WRAP))
        {
            // выполнить тест
            knownTest(kdfAlgorithm, new byte[] {
                (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, 
                (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, 
                (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, 
                (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f, 
                (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13
            }, new byte[] {
                (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, 
                (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef, 
                (byte)0xfe, (byte)0xdc, (byte)0xba, (byte)0x98, 
                (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x01,            
                (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, 
                (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef, 
                (byte)0xfe, (byte)0xdc, (byte)0xba, (byte)0x98, 
                (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x01,            
                (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, 
                (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef, 
                (byte)0xfe, (byte)0xdc, (byte)0xba, (byte)0x98, 
                (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x01,            
                (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, 
                (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef, 
                (byte)0xfe, (byte)0xdc, (byte)0xba, (byte)0x98, 
                (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x01            
            }, new byte[] {
                (byte)0x48, (byte)0x95, (byte)0x0c, (byte)0x46, 
                (byte)0xe0, (byte)0x53, (byte)0x00, (byte)0x75, 
                (byte)0x40, (byte)0x3c, (byte)0xce, (byte)0x72, 
                (byte)0x88, (byte)0x96, (byte)0x04, (byte)0xe0
            });
        }
    }
}
