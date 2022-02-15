using System;

namespace Aladdin.CAPI.ANSI.Derive
{
    ///////////////////////////////////////////////////////////////////////////
    // Наследование ключа X.942
    ///////////////////////////////////////////////////////////////////////////
    public class X942KDF : KeyDerive
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 

	    // алгоритм хэширования и идентификатор алгоритма шифрования ключа
	    private CAPI.Hash hashAlgorithm; private string wrapOID; 

	    // конструктор
	    public X942KDF(CAPI.Hash hashAlgorithm, string wrapOID) 
        { 
            // сохранить переданные параметры
            this.hashAlgorithm = RefObject.AddRef(hashAlgorithm); this.wrapOID = wrapOID; 
        }
        // освободить ресурсы 
        protected override void OnDispose()
        {
            // освободить ресурсы 
            RefObject.Release(hashAlgorithm); base.OnDispose();
        }
	    // сгенерировать блок данных
	    public override ISecretKey DeriveKey(ISecretKey key, 
            byte[] random, SecretKeyFactory keyFactory, int deriveSize)
	    {
            // проверить наличие размера
            if (deriveSize < 0) throw new InvalidOperationException(); 
        
            // при указании случайных данных
            if (random != null) 
            {
                // проверить корректность параметров
                if (wrapOID != null && random.Length != 64) throw new ArgumentException(); 
            }
            // проверить корректность ключа
            byte[] ZZ = key.Value; if (ZZ == null) throw new InvalidKeyException(); 
        
            // определить размер хэш-значения
            int hashLen = hashAlgorithm.HashSize; byte[] KEK = new byte[deriveSize];

            // для каждого блока ключа шифрования ключа
            for (int i = 0; i < (deriveSize + hashLen - 1) / hashLen; i++)
            {
                // закодировать номер блока
                byte[] counter = Math.Convert.FromInt32(i + 1, Endian);

                // при указании идентификатора алгоритма
                byte[] KM = ZZ; if (wrapOID != null)
                { 
                    // закодировать случайные данные
                    ASN1.OctetString partyAInfo = (random != null) ? new ASN1.OctetString(random) : null; 

                    // закодировать размер ключа шифрования ключа
                    ASN1.OctetString suppPubInfo = new ASN1.OctetString(
                        Math.Convert.FromInt32(deriveSize * 8, Endian)
                    ); 
                    // закодировать данные для хэширования
                    ASN1.ANSI.X942.KeySpecificInfo specificInfo = new ASN1.ANSI.X942.KeySpecificInfo(
                        new ASN1.ObjectIdentifier(wrapOID), new ASN1.OctetString(counter)
                    );
                    // закодировать данные для хэширования
                    ASN1.ANSI.X942.OtherInfo otherInfo = new ASN1.ANSI.X942.OtherInfo(
                        specificInfo, partyAInfo, suppPubInfo
                    ); 
                    // закодировать данные для хэширования
                    KM = Arrays.Concat(ZZ, otherInfo.Encoded);
                }
                // закодировать данные для хэширования
                else if (random != null) KM = Arrays.Concat(ZZ, random);

                // захэшировать данные
                byte[] hash = hashAlgorithm.HashData(KM, 0, KM.Length); 

                // скопировать часть ключа
                if (deriveSize >= (i + 1) * hashLen) Array.Copy(hash, 0, KEK, i * hashLen, hashLen); 

                // скопировать часть ключа
                else Array.Copy(hash, 0, KEK, i * hashLen, deriveSize - i * hashLen); 
            }
            return keyFactory.Create(KEK); 
	    }
        ////////////////////////////////////////////////////////////////////////////
        // Тест известного ответа
        ////////////////////////////////////////////////////////////////////////////
        public static void TestSHA1(CAPI.Hash sha1)
        {
            // создать алгоритм наследования ключа
            using (KeyDerive kdfAlgorithm = new X942KDF(
                sha1, ASN1.ISO.PKCS.PKCS9.OID.smime_tdes192_wrap))
            {
                // выполнить тест
                KnownTest(kdfAlgorithm, new byte[] {
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
            using (KeyDerive kdfAlgorithm = new X942KDF(
                sha1, ASN1.ISO.PKCS.PKCS9.OID.smime_rc2_128_wrap))
            {
                // выполнить тест
                KnownTest(kdfAlgorithm, new byte[] {
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
}
