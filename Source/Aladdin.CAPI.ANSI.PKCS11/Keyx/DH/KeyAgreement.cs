using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Keyx.DH
{
    ///////////////////////////////////////////////////////////////////////////
    // Формирование общего ключа Diffie-Hellman
    ///////////////////////////////////////////////////////////////////////////
    public class KeyAgreement : CAPI.PKCS11.KeyAgreement
    {    
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 
    
        // идентификатор алгоритма шифрования ключа
        private ulong kdf; private string keyWrapOID;
    
	    // конструктор
	    public KeyAgreement(CAPI.PKCS11.Applet applet) : this(applet, API.CKD_NULL, null) {}
    
	    // конструктор
	    public KeyAgreement(CAPI.PKCS11.Applet applet, ulong kdf, string keyWrapOID) : base(applet) 
	    { 
		    // сохранить переданные параметры
		    this.kdf = kdf; this.keyWrapOID = keyWrapOID;
        } 
        protected override CAPI.KeyAgreement CreateSoftwareAlgorithm(IParameters parameters)
        {
            // создать программный алгоритм
            if (kdf == API.CKD_NULL) return new ANSI.Keyx.DH.KeyAgreement(); 
        
            // указать параметры алгоритма хэширования
            Mechanism mechanism = new Mechanism(API.CKM_SHA_1); 
        
            // создать алгоритм хэширования
            using (CAPI.Hash hashAlgorithm = Creator.CreateHash(
                Applet.Provider, Applet, mechanism))
            {
                // проверить наличие алгоритма
                if (hashAlgorithm == null) throw new NotSupportedException(); 
            
                // создать программный алгоритм
                return new ANSI.Keyx.DH.KeyAgreement(hashAlgorithm, keyWrapOID); 
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
	    protected override Mechanism GetParameters(
            CAPI.PKCS11.Session sesssion, IPublicKey publicKey, byte[] random, int keySize)
        {
            // скорректировать случайные данные
            if (kdf == API.CKD_NULL) random = null;

            // выполнить преобразование ключа
            CAPI.ANSI.X942.IPublicKey dhPublicKey = (CAPI.ANSI.X942.IPublicKey)publicKey; 
        
            // закодировать значение ключа
            byte[] y = Math.Convert.FromBigInteger(dhPublicKey.Y, Endian);
        
            // вернуть параметры алгоритма
            return new Mechanism(API.CKM_X9_42_DH_DERIVE, 
                new Parameters.CK_X9_42_DH1_DERIVE_PARAMS(kdf, random, y)
            ); 
        }
        // согласовать общий ключ
	    public override ISecretKey DeriveKey(IPrivateKey privateKey, 
		    IPublicKey publicKey, byte[] random, SecretKeyFactory keyFactory, int keySize) 
        {
            // обработать отсутствие идентификатора
            if (keyWrapOID == null) return base.DeriveKey(privateKey, publicKey, random, keyFactory, keySize); 
        
            // при наличии эфемерного ключа
            if (privateKey.Scope == null && !Applet.Provider.CanImportSessionPair(Applet))
            {
                // вызвать базовую реализацию
                return base.DeriveKey(privateKey, publicKey, random, keyFactory, keySize); 
            }
            // закодировать случайные данные
            ASN1.OctetString partyAInfo = (random != null) ? new ASN1.OctetString(random) : null; 

            // закодировать размер ключа шифрования ключа
            ASN1.OctetString suppPubInfo = new ASN1.OctetString(Math.Convert.FromInt32(keySize * 8, Endian)); 
        
            // выделить память для ключа
            byte[] value = new byte[keySize]; int hashLen = 20; if (keySize <= hashLen)
            {
                // закодировать номер блока
                byte[] counter = Math.Convert.FromInt32(1, Endian);
            
                // закодировать данные для хэширования
                ASN1.ANSI.X942.KeySpecificInfo specificInfo = new ASN1.ANSI.X942.KeySpecificInfo(
                    new ASN1.ObjectIdentifier(keyWrapOID), new ASN1.OctetString(counter)
                );
                // закодировать данные для хэширования
                ASN1.ANSI.X942.OtherInfo otherInfo = new ASN1.ANSI.X942.OtherInfo(
                    specificInfo, partyAInfo, suppPubInfo
                ); 
                // выполнить наследование ключа
                return base.DeriveKey(privateKey, publicKey, otherInfo.Encoded, keyFactory, keySize); 
            }
            // для каждого блока ключа шифрования ключа
            for (int i = 0; i < (keySize + hashLen - 1) / hashLen; i++)
            {
                // закодировать номер блока
                byte[] counter = Math.Convert.FromInt32(i + 1, Endian);
            
                // закодировать данные для хэширования
                ASN1.ANSI.X942.KeySpecificInfo specificInfo = new ASN1.ANSI.X942.KeySpecificInfo(
                    new ASN1.ObjectIdentifier(keyWrapOID), new ASN1.OctetString(counter)
                );
                // закодировать данные для хэширования
                ASN1.ANSI.X942.OtherInfo otherInfo = new ASN1.ANSI.X942.OtherInfo(
                    specificInfo, partyAInfo, suppPubInfo
                ); 
                // выполнить наследование ключа
                using (ISecretKey key = base.DeriveKey(privateKey, 
                    publicKey, otherInfo.Encoded, SecretKeyFactory.Generic, hashLen))
                {
                    // проверить наличие значения
                    byte[] keyValue = key.Value; if (keyValue == null) 
                    {
                        // при ошибке выбросить исключение
                        throw new Aladdin.PKCS11.Exception(API.CKR_KEY_UNEXTRACTABLE); 
                    }
                    // определить размер части ключа
                    int size = (keySize >= (i + 1) * hashLen) ? hashLen : (keySize - i * hashLen); 
            
                    // скопировать часть ключа
                    Array.Copy(keyValue, 0, value, i * hashLen, size); 
                }
            }
            // вернуть созданный ключ
            return keyFactory.Create(value); 
        }
    }
}
