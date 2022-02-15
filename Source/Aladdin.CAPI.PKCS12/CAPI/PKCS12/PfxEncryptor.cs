using System; 
using System.IO; 

namespace Aladdin.CAPI.PKCS12
{
    ///////////////////////////////////////////////////////////////////////////
	// Зашифрование данных
    ///////////////////////////////////////////////////////////////////////////
	public abstract class PfxEncryptor
    {
        // зашифровать данные
        public abstract byte[] Encrypt(byte[] data); 

        ////////////////////////////////////////////////////////////////////////////
        // Шифрование данных в контейнере
        ////////////////////////////////////////////////////////////////////////////
        public class Container : PfxEncryptor
        {
            // используемый контейнер и тип защиты
            private PfxContainer container; PBE.PBECulture culture; 
            // тип данных
            private Type encryptionType; 
            
            // конструктор
            public Container(PfxContainer container, PBE.PBECulture culture, Type encryptionType)
            {
                // сохранить переданные параметры
                this.container = container; this.culture = culture; 
                
                // сохранить переданные параметры
                this.encryptionType = encryptionType; 
            }
            // функция зашифрования
            public override byte[] Encrypt(byte[] data) 
            {
                // зашифровать данные
                return container.Encrypt(culture, data, encryptionType); 
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Шифрование личного ключа на симметричном ключе
        ////////////////////////////////////////////////////////////////////////////
        public class PrivateKeyCipherWrap : PfxEncryptor
        {
            // используемый контейнер
            private PfxEncryptedContainer container;  
            // параметры шифрования
            private ASN1.ISO.AlgorithmIdentifier cipherParameters; 
        
            // конструктор
            public PrivateKeyCipherWrap(PfxEncryptedContainer container, 
                ASN1.ISO.AlgorithmIdentifier cipherParameters)
            {
                // сохранить переданные параметры
                this.container = container; this.cipherParameters = cipherParameters; 
            }
            // функция зашифрования
            public override byte[] Encrypt(byte[] data) 
            {
			    // раскодировать данные
                ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo privateKeyInfo = 
                    new ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo(ASN1.Encodable.Decode(data));
                try { 
                    // зашифровать данные
                    return CMS.EncryptPrivateKey(container.Factory, null, 
                        container.EncryptionKey, cipherParameters, privateKeyInfo).Encoded; 
                }
                // обработать неожидаемое исключение
                catch (InvalidKeyException e) { throw new InvalidDataException(e.Message, e); }
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Шифрование личного ключа на открытом ключе
        ////////////////////////////////////////////////////////////////////////////
        public class PrivateKeyKeyxWrap : PfxEncryptor
        {
            // используемый контейнер
            private PfxEnvelopedContainer container;  
            // параметры шифрования
            private ASN1.ISO.AlgorithmIdentifier encryptionParameters; 
        
            // конструктор
            public PrivateKeyKeyxWrap(PfxEnvelopedContainer container, 
                ASN1.ISO.AlgorithmIdentifier encryptionParameters)
            {
                // сохранить переданные параметры
                this.container = container; this.encryptionParameters = encryptionParameters; 
            }
            // функция зашифрования
            public override byte[] Encrypt(byte[] data) 
            {
                // получить фабрику алгоритмов
                Factory factory = container.EnvelopePrivateKey.Factory; 

			    // раскодировать данные
                ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo privateKeyInfo = 
                    new ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo(ASN1.Encodable.Decode(data)); 

                // зашифровать данные
			    return CMS.EncryptPrivateKey(factory, null, container.Rand,  
                    container.EnvelopeCertificate, encryptionParameters, privateKeyInfo).Encoded; 
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Шифрование данных на симметричном ключе
        ////////////////////////////////////////////////////////////////////////////
        public class CipherWrap : PfxEncryptor
        {
            // используемый контейнер и тип данных
            private PfxEncryptedContainer container; private string dataType;
            // параметры алгоритма
            private ASN1.ISO.AlgorithmIdentifier cipherParameters; ASN1.ISO.Attributes attributes; 
        
            // конструктор
            public CipherWrap(PfxEncryptedContainer container, 
                ASN1.ISO.AlgorithmIdentifier cipherParameters, 
                ASN1.ISO.Attributes attributes, string dataType)
            {
                // сохранить переданные параметры
                this.container = container; this.cipherParameters = cipherParameters;
            
                // сохранить переданные параметры
                this.attributes = attributes; this.dataType = dataType;
            }
            // функция зашифрования
            public override byte[] Encrypt(byte[] data)
            {
			    // указать тип данных 
			    CMSData cmsData = new CMSData(dataType, data);
                try { 
                    // зашифровать данные
                    return CMS.EncryptData(container.Factory, null, 
                        container.EncryptionKey, cipherParameters, cmsData, attributes).Encoded; 
                }
                // обработать неожидаемое исключение
                catch (InvalidKeyException e) { throw new InvalidDataException(e.Message, e); }
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Шифрование данных на пароле
        ////////////////////////////////////////////////////////////////////////////
        public class PasswordWrap : PfxEncryptor
        {
            // используемый контейнер
            private PfxEncryptedContainer container; 

            // параметры шифрования и наследования ключа
            private ASN1.ISO.AlgorithmIdentifier cipherParameters; 
            private ASN1.ISO.AlgorithmIdentifier keyDeriveParameters; 
            private ASN1.ISO.AlgorithmIdentifier keyWrapParameters; 

            // тип данных и атрибуты
            private string dataType; private ASN1.ISO.Attributes attributes;

            // конструктор
            public PasswordWrap(PfxEncryptedContainer container, 
                ASN1.ISO.AlgorithmIdentifier cipherParameters, 
                ASN1.ISO.AlgorithmIdentifier keyDeriveParameters, 
                ASN1.ISO.AlgorithmIdentifier keyWrapParameters,
                string dataType, ASN1.ISO.Attributes attributes)
            {
                // сохранить переданные параметры
                this.container = container; this.dataType = dataType; this.attributes = attributes; 
            
                // сохранить переданные параметры
                this.cipherParameters    = cipherParameters; 
                this.keyDeriveParameters = keyDeriveParameters; 
                this.keyWrapParameters   = keyWrapParameters; 
            }
            // функция зашифрования
            public override byte[] Encrypt(byte[] data) 
            {
			    // указать тип данных 
			    CMSData cmsData = new CMSData(dataType, data);
                try { 
                    // зашифровать данные
                    return CMS.PasswordEncryptData(container.Factory, null, container.Rand, 
                        new ISecretKey[] { container.EncryptionKey }, cipherParameters,  
                        new ASN1.ISO.AlgorithmIdentifier[] { keyDeriveParameters }, 
                        new ASN1.ISO.AlgorithmIdentifier[] { keyWrapParameters   }, 
                        cmsData, attributes).Encoded; 
                }
                // обработать неожидаемое исключение
                catch (InvalidKeyException e) { throw new InvalidDataException(e.Message, e); }
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Шифрование данных на пароле
        ////////////////////////////////////////////////////////////////////////////
        public class CultureWrap : PfxEncryptor
        {
            // используемый контейнер
            private PfxEncryptedContainer container; private PBE.PBECulture culture; 
            // тип данных и атрибуты
            private string dataType; private ASN1.ISO.Attributes attributes;

            // конструктор
            public CultureWrap(PfxEncryptedContainer container, 
                PBE.PBECulture culture, string dataType, ASN1.ISO.Attributes attributes)
            {
                // сохранить переданные параметры
                this.container = container; this.culture = culture; 
            
                // сохранить переданные параметры
                this.dataType = dataType; this.attributes = attributes; 
            }
            // функция зашифрования
            public override byte[] Encrypt(byte[] data) 
            {
			    // указать тип данных 
			    CMSData cmsData = new CMSData(dataType, data);
                try { 
                    // зашифровать данные
                    return culture.PasswordEncryptData(container.Factory, null, container.Rand, 
                        true, container.EncryptionKey, cmsData, attributes).Encoded; 
                }
                // обработать неожидаемое исключение
                catch (InvalidKeyException e) { throw new InvalidDataException(e.Message, e); }
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Шифрование данных на открытом ключе
        ////////////////////////////////////////////////////////////////////////////
        public class KeyxWrap : PfxEncryptor
        {
            // используемый контейнер
            private PfxEnvelopedContainer container; 
 
            // параметры шифрования данных и ключа
		    private ASN1.ISO.AlgorithmIdentifier cipherParameters; 
		    private ASN1.ISO.AlgorithmIdentifier transportParameters;
 
            // тип данных и атрибуты
            private string dataType; private ASN1.ISO.Attributes attributes;

            // конструктор
            public KeyxWrap(PfxEnvelopedContainer container, 
                ASN1.ISO.AlgorithmIdentifier cipherParameters, 
                ASN1.ISO.AlgorithmIdentifier transportParameters, 
                string dataType, ASN1.ISO.Attributes attributes)
            {
                // сохранить переданные параметры
                this.container = container; this.dataType = dataType; this.attributes = attributes; 
            
                // сохранить переданные параметры
                this.cipherParameters = cipherParameters; this.transportParameters = transportParameters; 
            }
            // функция зашифрования
            public override byte[] Encrypt(byte[] data) 
            {
                // получить фабрику алгоритмов
                Factory factory = container.EnvelopePrivateKey.Factory; 

			    // указать тип данных 
			    CMSData cmsData = new CMSData(dataType, data); 
            
                // зашифровать данные
                return CMS.KeyxEncryptData(factory, null, container.Rand,  
                    new Certificate[] { container.EnvelopeCertificate }, cipherParameters,  
                    new ASN1.ISO.AlgorithmIdentifier[] { transportParameters }, 
                    cmsData, attributes).Encoded; 
            }
        }
    }
}
