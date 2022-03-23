package aladdin.capi.pkcs12;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkcs.pkcs8.*; 
import aladdin.capi.*;
import aladdin.capi.Certificate;
import aladdin.capi.pbe.*;
import java.security.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Зашифрование данных
///////////////////////////////////////////////////////////////////////////////
public abstract class PfxEncryptor
{ 
    // зашифровать данные
    public abstract byte[] encrypt(byte[] data) throws IOException; 
    
    ////////////////////////////////////////////////////////////////////////////
    // Шифрование данных в контейнере
    ////////////////////////////////////////////////////////////////////////////
    public static class Container extends PfxEncryptor
    {
        // используемый контейнер 
        private final PfxContainer container; private final PBECulture culture; 
        // тип данных
        private final Class<? extends IEncodable> encryptionType; 
        
        // конструктор
        public Container(PfxContainer container, 
            PBECulture culture, Class<? extends IEncodable> encryptionType)
        {
            // сохранить переданные параметры
            this.container = container; this.culture = culture; 
            
            // сохранить переданные параметры
            this.encryptionType = encryptionType; 
        }
        // функция зашифрования
        @Override public byte[] encrypt(byte[] data) throws IOException
        {
            // зашифровать данные
            return container.encrypt(culture, data, encryptionType); 
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Шифрование личного ключа на симметричном ключе
    ////////////////////////////////////////////////////////////////////////////
    public static class PrivateKeyCipherWrap extends PfxEncryptor
    {
        // используемый контейнер
        private final PfxEncryptedContainer container;  
        
        // параметры шифрования
        private final AlgorithmIdentifier cipherParameters; 
        
        // конструктор
        public PrivateKeyCipherWrap(PfxEncryptedContainer container, 
            AlgorithmIdentifier cipherParameters)
        {
            // сохранить переданные параметры
            this.container = container; this.cipherParameters = cipherParameters;
        }
        // функция зашифрования
        @Override public byte[] encrypt(byte[] data) throws IOException
        {
    	    // раскодировать данные
            PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(Encodable.decode(data)); 
            try { 
                // зашифровать данные
                return CMS.encryptPrivateKey(container.factory(), null, 
                    container.encryptionKey(), cipherParameters, privateKeyInfo).encoded(); 
            }
            // обработать неожидаемое исключение
            catch (InvalidKeyException e) { throw new IOException(e); }
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Шифрование личного ключа на открытом ключе
    ////////////////////////////////////////////////////////////////////////////
    public static class PrivateKeyKeyxWrap extends PfxEncryptor
    {
        // используемый контейнер
        private final PfxEnvelopedContainer container; 
        // параметры шифрования
        private final AlgorithmIdentifier encryptionParameters; 
        
        // конструктор
        public PrivateKeyKeyxWrap(PfxEnvelopedContainer container, 
            AlgorithmIdentifier encryptionParameters)
        {
            // сохранить переданные параметры
            this.container = container; 
            
            // сохранить переданные параметры
            this.encryptionParameters = encryptionParameters;
        }
        // функция зашифрования
        @Override public byte[] encrypt(byte[] data) throws IOException
        {
            // получить фабрику алгоритмов
            Factory factory = container.envelopePrivateKey().factory(); 
            
			// раскодировать данные
			PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(Encodable.decode(data)); 

            // зашифровать данные
			return CMS.encryptPrivateKey(factory, null, container.rand(), 
                container.envelopeCertificate(), encryptionParameters, privateKeyInfo).encoded(); 
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Шифрование данных на симметричном ключе
    ////////////////////////////////////////////////////////////////////////////
    public static class CipherWrap extends PfxEncryptor
    {
        // используемый контейнер и тип данных
        private final PfxEncryptedContainer container; private final String dataType;
        // параметры алгоритма и набор атрибутов
        private final AlgorithmIdentifier cipherParameters; private final Attributes attributes;
        
        public CipherWrap(PfxEncryptedContainer container, 
            AlgorithmIdentifier cipherParameters, Attributes attributes, String dataType)
        {
            // сохранить переданные параметры
            this.container = container; this.cipherParameters = cipherParameters;
            
            // сохранить переданные параметры
            this.attributes = attributes; this.dataType = dataType;
        }
        // функция зашифрования
        @Override public byte[] encrypt(byte[] data) throws IOException
        {
			// указать тип данных 
			CMSData cmsData = new CMSData(dataType, data); 
            try { 
                // вернуть закодированное представление
                return CMS.encryptData(container.factory(), null, 
                    container.encryptionKey(), cipherParameters, cmsData, attributes).encoded(); 
            }
            // обработать неожидаемое исключение
            catch (InvalidKeyException e) { throw new IOException(e); }
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Шифрование данных на пароле
    ////////////////////////////////////////////////////////////////////////////
    public static class PasswordWrap extends PfxEncryptor
    {
        // используемый контейнер
        private final PfxEncryptedContainer container; 
        
        // параметры шифрования и наследования ключа
        private final AlgorithmIdentifier cipherParameters; 
        private final AlgorithmIdentifier keyDeriveParameters; 
        private final AlgorithmIdentifier keyWrapParameters; 
        
        // тип данных и атрибуты
        private final String dataType; private final Attributes attributes; 
        
        public PasswordWrap(PfxEncryptedContainer container, 
            AlgorithmIdentifier cipherParameters, AlgorithmIdentifier keyDeriveParameters, 
            AlgorithmIdentifier keyWrapParameters, String dataType, Attributes attributes)
        {
            // сохранить переданные параметры
            this.container = container; this.dataType = dataType; this.attributes = attributes; 
            
            // сохранить переданные параметры
            this.cipherParameters    = cipherParameters; 
            this.keyDeriveParameters = keyDeriveParameters; 
            this.keyWrapParameters   = keyWrapParameters; 
        }
        // функция зашифрования
        @Override public byte[] encrypt(byte[] data) throws IOException
        {
			// указать тип данных 
			CMSData cmsData = new CMSData(dataType, data); 
            try { 
                // зашифровать данные
                return CMS.passwordEncryptData(
                    container.factory(), null, container.rand(), 
                    new ISecretKey[] { container.encryptionKey() }, 
                    cipherParameters, 
                    new AlgorithmIdentifier[] { keyDeriveParameters }, 
                    new AlgorithmIdentifier[] { keyWrapParameters   }, 
                    cmsData, attributes).encoded(); 
            }
            // обработать неожидаемое исключение
            catch (InvalidKeyException e) { throw new IOException(e); }
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Шифрование данных на пароле
    ////////////////////////////////////////////////////////////////////////////
    public static class CultureWrap extends PfxEncryptor
    {
        // используемый контейнер
        private final PfxEncryptedContainer container; 
        // используемые параметры и тип данных
        private final PBECulture culture; private final String dataType; 
        // атрибуты
        private final Attributes attributes; 
        
        public CultureWrap(PfxEncryptedContainer container, 
            PBECulture culture, String dataType, Attributes attributes)
        {
            // сохранить переданные параметры
            this.container = container; this.culture = culture; 
            
            // сохранить переданные параметры
            this.dataType = dataType; this.attributes = attributes; 
        }
        // функция зашифрования
        @Override public byte[] encrypt(byte[] data) throws IOException
        {
			// указать тип данных 
			CMSData cmsData = new CMSData(dataType, data); 
            try { 
                // зашифровать данные
                return culture.passwordEncryptData(
                    container.factory(), null, container.rand(), 
                    container.encryptionKey(), cmsData, attributes).encoded(); 
            }
            // обработать неожидаемое исключение
            catch (InvalidKeyException e) { throw new IOException(e); }
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Шифрование данных на открытом ключе
    ////////////////////////////////////////////////////////////////////////////
    public static class KeyxWrap extends PfxEncryptor
    {
        // используемый контейнер
        private final PfxEnvelopedContainer container; 
        
        // параметры шифрования данных и ключа
		private final AlgorithmIdentifier cipherParameters; 
		private final AlgorithmIdentifier transportParameters; 

        // тип данных и атрибуты
        private final String dataType; private final Attributes attributes; 
        
        public KeyxWrap(PfxEnvelopedContainer container, 
            AlgorithmIdentifier cipherParameters, 
            AlgorithmIdentifier transportParameters, 
            String dataType, Attributes attributes)
        {
            // сохранить переданные параметры
            this.container = container; this.dataType = dataType; this.attributes = attributes;
            
            // сохранить переданные параметры
            this.cipherParameters    = cipherParameters; 
            this.transportParameters = transportParameters; 
        }
        // функция зашифрования
        @Override public byte[] encrypt(byte[] data) throws IOException
        {
            // получить фабрику алгоритмов
            Factory factory = container.envelopePrivateKey().factory(); 
                
			// указать тип данных 
			CMSData cmsData = new CMSData(dataType, data); 
            
            // зашифровать данные
            return CMS.keyxEncryptData(factory, null, container.rand(),  
                new Certificate[] { container.envelopeCertificate() }, 
                new AlgorithmIdentifier[] { transportParameters}, 
                cipherParameters, cmsData, attributes).encoded(); 
        }
    }
}
