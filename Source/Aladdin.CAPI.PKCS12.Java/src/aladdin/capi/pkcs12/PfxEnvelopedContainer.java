package aladdin.capi.pkcs12;
import aladdin.*; 
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkcs.*;
import aladdin.asn1.iso.pkcs.pkcs7.*; 
import aladdin.asn1.iso.pkcs.pkcs8.*; 
import aladdin.asn1.iso.pkcs.pkcs12.*; 
import aladdin.capi.*;
import aladdin.capi.Certificate;
import aladdin.capi.pbe.*;
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Зашифрованный на открытом ключе контейнер PKCS12
///////////////////////////////////////////////////////////////////////////
public class PfxEnvelopedContainer extends PfxContainer
{
    // личный ключ и сертификат
    private	IPrivateKey privateKey;	private	Certificate certificate; 
    // алгоритмы по умолчанию
    private aladdin.capi.Culture culture;

	// конструктор
	protected PfxEnvelopedContainer(PFX content, IRand rand) throws IOException  
	{ 
        // сохранить переданные параметры
        super(content, rand); privateKey = null; certificate = null;
	}
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException   
    {
        // освободить выделенные ресурсы
		RefObject.release(privateKey); super.onClose();
    }
    // личный ключ и сертификат
    public final IPrivateKey envelopePrivateKey () { return privateKey;  } 
    public final Certificate envelopeCertificate() { return certificate; }
    
	// установить ключи
	public final void setEnvelopeKeys(IPrivateKey privateKey, 
        Certificate certificate, aladdin.capi.Culture culture) throws IOException
	{
        // освободить выделенные ресурсы
        RefObject.release(this.privateKey); this.privateKey = null;
        
		// сохранить переданные параметры
		this.privateKey = RefObject.addRef(privateKey); 
        
        // расшифровать данные
        this.certificate = certificate; this.culture = culture; super.decrypt(this);
    }
    // переустановить ключи
    public void changeEnvelopeKeys(
        IPrivateKey privateKey, Certificate certificate) throws IOException
	{
		// проверить наличие сертификата
		if (this.certificate == null || this.privateKey == null) throw new AuthenticationException();

		// сохранить старые ключи
		IPrivateKey oldPrivateKey = this.privateKey; Certificate oldCertificate = this.certificate; 

        // указать новые ключи
        this.privateKey = RefObject.addRef(privateKey); this.certificate = certificate; 

        // обработать изменение данных
        try { change(); RefObject.release(oldPrivateKey); } 
        
        // при возникновении исключения
        catch (IOException e) { RefObject.release(privateKey); 

            // восстановить ключи
            this.privateKey = oldPrivateKey; this.certificate = oldCertificate; throw e; 
        }
    }
	// зашифровать элемент
	@Override public byte[] encrypt(PBECulture culturePBE, byte[] data, 
        Class<? extends IEncodable> encryptionType) throws IOException
	{
		// указать тип по умолчанию
		if (encryptionType == null) encryptionType = EnvelopedData.class; 

		// проверить наличие сертификата
		if (certificate == null || privateKey == null) throw new AuthenticationException();
        
        // в зависимости от типа
        if (encryptionType.equals(EncryptedPrivateKeyInfo.class))
        {
            // получить параметры алгоритма шифрования
            AlgorithmIdentifier ciphermentParameters = culture.ciphermentAlgorithm(rand()); 
                
            // проверить указание параметров
            if (ciphermentParameters == null) throw new UnsupportedOperationException();  
                
            // указать способ шифрования
            PfxEncryptor encryptor = new PfxEncryptor.PrivateKeyKeyxWrap(
                this, ciphermentParameters
            ); 
            // зашифровать личный ключ
            return encryptor.encrypt(data); 
        }
        else if (encryptionType.equals(EnvelopedData.class))
        {
            // получить параметры алгоритма шифрования
            AlgorithmIdentifier cipherParameters = culture.cipherAlgorithm(rand()); 
                
            // проверить указание параметров
            if (cipherParameters == null) throw new UnsupportedOperationException();  
                
            // получить параметры шифрования
            AlgorithmIdentifier keyxParameters = culture.keyxParameters(
                privateKey.factory(), privateKey.scope(), rand(), certificate.keyUsage()
            ); 
            // проверить указание параметров
            if (keyxParameters == null) throw new UnsupportedOperationException();
                
            // указать способ шифрования
            PfxEncryptor encryptor = new PfxEncryptor.KeyxWrap(
                this, cipherParameters, keyxParameters, 
                aladdin.asn1.iso.pkcs.pkcs7.OID.DATA, null
            ); 
            // зашифровать данные
            return encryptor.encrypt(data); 
        }
		return null; 
	}
	// расшифровать элемент
	@Override public PfxData<byte[]> decrypt(byte[] data, 
        Class<? extends IEncodable> encryptionType) throws IOException
	{
		// проверить наличие ключа
		if (privateKey == null || certificate == null) throw new AuthenticationException();

		// в зависимости от типа
		if (encryptionType.equals(EncryptedPrivateKeyInfo.class))
		{
			// преобразовать тип данных
			EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = 
				new EncryptedPrivateKeyInfo(Encodable.decode(data)); 

			// указать функцию зашифрования
			PfxEncryptor encryptor = new PfxEncryptor.PrivateKeyKeyxWrap(
                this, encryptedPrivateKeyInfo.encryptionAlgorithm()
            ); 
			// расшифровать данные
			data = CMS.decryptPrivateKey(privateKey, encryptedPrivateKeyInfo).encoded();  

            // вернуть расшифрованные данные
            return new PfxData<byte[]>(data, encryptor); 
		}
		// в зависимости от типа
		else if (encryptionType.equals(EnvelopedData.class))
		{
			// раскодировать элемент
			EnvelopedData envelopedData = new EnvelopedData(Encodable.decode(data)); 

			// раскодировать структуру
			EncryptedContentInfo encryptedContentInfo = envelopedData.encryptedContentInfo(); 

			// раскодировать структуру
			RecipientInfos recipientInfos = envelopedData.recipientInfos(); 

			// раскодировать структуру
			KeyTransRecipientInfo recipientInfo = new KeyTransRecipientInfo(recipientInfos.get(0)); 
					
            // получить параметры алгоритма шифрования
            AlgorithmIdentifier cipherParameters = encryptedContentInfo.contentEncryptionAlgorithm(); 

            // создать алгоритм шифрования
            try (Cipher cipher = (Cipher)privateKey.factory().createAlgorithm(
                privateKey.scope(), cipherParameters, Cipher.class))
            {
                // при ошибке выбросить исключение
                if (cipher == null) throw new UnsupportedOperationException();
                
                // расшифровать ключ шифрования данных
                try (ISecretKey CEK = CMS.transportDecryptKey(privateKey, recipientInfo, cipher.keyFactory()))
                {
                    // указать функцию зашифрования
                    PfxEncryptor encryptor = new PfxEncryptor.KeyxWrap(this, 
                        encryptedContentInfo.contentEncryptionAlgorithm(), 
                        recipientInfo.keyEncryptionAlgorithm(), 
                        encryptedContentInfo.contentType().value(), envelopedData.unprotectedAttrs()
                    ); 
                    // расшифровать данные
                    data = CMS.decryptData(privateKey.factory(), privateKey.scope(), 
                        CEK, envelopedData.encryptedContentInfo(), envelopedData.unprotectedAttrs()).content; 

                    // вернуть расшифрованные данные
                    return new PfxData<byte[]>(data, encryptor); 
                }
                // обработать неожидаемую ошибку
                catch (InvalidKeyException e) { throw new RuntimeException(e); }
            }
		}
		return null; 
	}
	@Override protected void onChange(AuthenticatedSafe authenticatedSafe) throws IOException
	{
        // указать тип данных
        String oid = content.authSafe().contentType().value(); 

		// закодировать данные
		byte[] encoded = authenticatedSafe.encoded();  

        // закодировать данные
        ContentInfo contentInfo = new ContentInfo(
            new ObjectIdentifier(oid), new OctetString(encoded)
        ); 
        // закодировать контейнер
        content = new PFX(new Integer(3), contentInfo, null); 
	}
}
