using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Keyx.ECDH
{
    ///////////////////////////////////////////////////////////////////////////
    // Формирование общего ключа ECDH
    ///////////////////////////////////////////////////////////////////////////
    public class KeyAgreement : CAPI.PKCS11.KeyAgreement
    {    
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 
    
        // идентификатор алгоритма и диверсификации
        private ulong algID; private ulong kdf; 
        // параметры алгоритма шифрования ключа
        private ASN1.ISO.AlgorithmIdentifier keyWrapParameters;  
    
	    // конструктор
	    public KeyAgreement(CAPI.PKCS11.Applet applet, ulong algID) 
            
            // сохранить переданные параметры
            : this(applet, algID, API.CKD_NULL, null) {}
    
	    // конструктор
	    public KeyAgreement(CAPI.PKCS11.Applet applet, ulong algID, 
            ulong kdf, ASN1.ISO.AlgorithmIdentifier keyWrapParameters) : base(applet)
	    { 
		    // сохранить переданные параметры
		    this.algID = algID; this.kdf = kdf; this.keyWrapParameters = keyWrapParameters;
        } 
        protected override CAPI.KeyAgreement CreateSoftwareAlgorithm(IParameters parameters)
        {
            // указать модификацию алгоритма
            bool cofactor = (algID == API.CKM_ECDH1_COFACTOR_DERIVE); 
        
            // создать программный алгоритм
            if (kdf == API.CKD_NULL) return new ANSI.Keyx.ECDH.KeyAgreement(cofactor); 
        
            ulong hashID = 0; switch (kdf)
            {
            case API.CKD_SHA1_KDF    : hashID = API.CKM_SHA_1;    break; 
            case API.CKD_SHA224_KDF  : hashID = API.CKM_SHA224;   break; 
            case API.CKD_SHA256_KDF  : hashID = API.CKM_SHA256;   break; 
            case API.CKD_SHA384_KDF  : hashID = API.CKM_SHA384;   break; 
            case API.CKD_SHA512_KDF  : hashID = API.CKM_SHA512;   break; 
            case API.CKD_SHA3_224_KDF: hashID = API.CKM_SHA3_224; break; 
            case API.CKD_SHA3_256_KDF: hashID = API.CKM_SHA3_256; break; 
            case API.CKD_SHA3_384_KDF: hashID = API.CKM_SHA3_384; break; 
            case API.CKD_SHA3_512_KDF: hashID = API.CKM_SHA3_512; break; 
            }
            // проверить поддержку алгоритма
            if (hashID == 0) throw new NotSupportedException();
        
            // указать параметры алгоритма хэширования
            Mechanism mechanism = new Mechanism(hashID); 
        
            // создать алгоритм хэширования
            using (CAPI.Hash hashAlgorithm = Creator.CreateHash(
                Applet.Provider, Applet, mechanism))
            {
                // проверить наличие алгоритма
                if (hashAlgorithm == null) throw new NotSupportedException(); 
            
                // создать программный алгоритм
                return new ANSI.Keyx.ECDH.KeyAgreement(
                    cofactor, hashAlgorithm, keyWrapParameters
                ); 
            }
        }
        // сгенерировать случайные данные
        public override byte[] Generate(IParameters parameters, IRand rand)
        {
            // проверить необходимость генерации
            if (kdf == API.CKD_NULL) return null; 

            // сгенерировать случайные данные
            byte[] random = new byte[64]; rand.Generate(random, 0, 64); return random;   
        }
	    // параметры алгоритма
	    protected override Mechanism GetParameters(CAPI.PKCS11.Session sesssion, 
		    IPublicKey publicKey, byte[] random, int keySize)
        {
            // скорректировать случайные данные
            if (kdf == API.CKD_NULL) random = null;
        
            // преобразовать тип параметров
            ANSI.X962.IParameters ecParameters = (ANSI.X962.IParameters)publicKey.Parameters; 
        
            // выполнить преобразование ключа
            ANSI.X962.IPublicKey ecPublicKey = (ANSI.X962.IPublicKey)publicKey; 
        
            // закодировать базовую точку эллиптической кривой
            byte[] encoded = ecParameters.Curve.Encode(ecPublicKey.Q, EC.Encoding.Uncompressed); 

            // вернуть параметры алгоритма
            return new Mechanism(algID, new Parameters.CK_ECDH1_DERIVE_PARAMS(kdf, random, encoded)); 
        }
        // согласовать общий ключ
	    public override ISecretKey DeriveKey(IPrivateKey privateKey, 
		    IPublicKey publicKey, byte[] random, SecretKeyFactory keyFactory, int keySize)
        {
            // обработать отсутствие идентификатора
            if (keyWrapParameters == null) return base.DeriveKey(privateKey, publicKey, random, keyFactory, keySize); 
        
            // при наличии эфемерного ключа
            if (privateKey.Scope == null && !Applet.Provider.CanImportSessionPair(Applet))
            {
                // вызвать базовую реализацию
                return base.DeriveKey(privateKey, publicKey, random, keyFactory, keySize); 
            }
            // закодировать случайные данные
            ASN1.OctetString entityUInfo = (random != null) ? new ASN1.OctetString(random) : null; 
        
            // закодировать размер ключа в битах
            ASN1.OctetString suppPubInfo = new ASN1.OctetString(Math.Convert.FromInt32(keySize * 8, Endian));
            
            // объединить закодированные данные
            ASN1.ANSI.X962.SharedInfo sharedInfo = new ASN1.ANSI.X962.SharedInfo(
                keyWrapParameters, entityUInfo, null, suppPubInfo, null
            ); 
            // выполнить наследование ключа
            return base.DeriveKey(privateKey, publicKey, sharedInfo.Encoded, keyFactory, keySize); 
        }
    }
}
