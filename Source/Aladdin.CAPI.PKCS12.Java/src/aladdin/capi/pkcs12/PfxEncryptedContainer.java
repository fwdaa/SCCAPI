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
import aladdin.capi.pbe.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Зашифрованный на пароле контейнер PKCS12
///////////////////////////////////////////////////////////////////////////
public class PfxEncryptedContainer extends PfxContainer
{
    // фабрика алгоритмов и ключ шифрования контейнера
    private final Factory factory; private ISecretKey key;	
    
	// конструктор
	protected PfxEncryptedContainer(PFX content, Factory factory, IRand rand) throws IOException
    { 
        // сохранить переданные параметры
        super(content, rand); this.factory = RefObject.addRef(factory); this.key = null; 
	}
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException   
    {
        // освободить выделенные ресурсы
		RefObject.release(key); RefObject.release(factory); super.onClose();
    }
    // фабрика алгоритмов
    public final Factory factory() { return factory; }

    // ключ шифрования контейнера
    public final ISecretKey encryptionKey() { return key; }
    
	// установить ключи
	public final void setEncryptionKey(ISecretKey key) throws IOException
	{
        // освободить выделенные ресурсы
        RefObject.release(this.key); this.key = null; 
        
		// закодировать пароль и расшифровать данные
		this.key = RefObject.addRef(key); super.decrypt(this);
    }
    // изменить пароль
    public final void changeEncryptionKey(ISecretKey key) throws IOException
	{
        // проверить наличие ключа
        if (this.key == null) throw new AuthenticationException(); 

        // указать новый ключ шифрования
		ISecretKey oldKey = this.key; this.key = RefObject.addRef(key);  

        // обработать изменение данных
        try { change(); RefObject.release(oldKey); } 
            
        // восстановить пароль при возникновении ошибки
        catch (IOException e) { RefObject.release(key); this.key = oldKey; throw e; }
    }
	// зашифровать элемент
	@Override public byte[] encrypt(PBECulture culture, 
        byte[] data, Class<? extends IEncodable> encryptionType) throws IOException
	{
		// проверить наличие пароля
		if (key == null) throw new AuthenticationException();

		// в зависимости от типа
		if (encryptionType != null && encryptionType.equals(EncryptedPrivateKeyInfo.class))
		{
            // указать способ шифрования
            PfxEncryptor encryptor = new PfxEncryptor.PrivateKeyCipherWrap(
                this, culture.cipherAlgorithm(rand())
            ); 
            // зашифровать личный ключ
            return encryptor.encrypt(data); 
		}
		else if (encryptionType == null || 
                 encryptionType.equals(EnvelopedData.class) || 
                 encryptionType.equals(EncryptedData.class))
		{
            // указать способ шифрования
            PfxEncryptor encryptor = new PfxEncryptor.CultureWrap(
                this, culture, aladdin.asn1.iso.pkcs.pkcs7.OID.DATA, null
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
		// проверить наличие пароля
		if (key == null) throw new IllegalStateException();

		// в зависимости от типа
		if (encryptionType.equals(EncryptedPrivateKeyInfo.class))
		{
			// преобразовать тип данных
			EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = 
				new EncryptedPrivateKeyInfo(Encodable.decode(data)); 
            try { 
                // указать функцию зашифрования
                PfxEncryptor encryptor = new PfxEncryptor.PrivateKeyCipherWrap(
                    this, encryptedPrivateKeyInfo.encryptionAlgorithm()
                );
                // расшифровать данные
                data = CMS.decryptPrivateKey(factory, null, key, encryptedPrivateKeyInfo).encoded(); 

                // вернуть расшифрованные данные
                return new PfxData<byte[]>(data, encryptor); 
            }
            // обработать неожидаемое исключение
            catch (InvalidKeyException e) { throw new IOException(e); }
		}
		// в зависимости от типа
		else if (encryptionType.equals(EnvelopedData.class))
		{
			// преобразовать тип данных
			EnvelopedData envelopedData = new EnvelopedData(Encodable.decode(data)); 

			// раскодировать структуру
			EncryptedContentInfo encryptedContentInfo = envelopedData.encryptedContentInfo(); 
					
			// раскодировать структуру
			RecipientInfos recipientInfos = envelopedData.recipientInfos(); 

			// раскодировать структуру
			PasswordRecipientInfo recipientInfo = new PasswordRecipientInfo(recipientInfos.get(0)); 
				
            // получить параметры алгоритма шифрования
            AlgorithmIdentifier cipherParameters = encryptedContentInfo.contentEncryptionAlgorithm(); 

            // создать алгоритм шифрования
            try (Cipher cipher = (Cipher)factory.createAlgorithm(null, cipherParameters, Cipher.class))
            {
                // при ошибке выбросить исключение
                if (cipher == null) throw new UnsupportedOperationException();
                
                // расшифровать ключ шифрования данных по паролю
                try (ISecretKey CEK = CMS.passwordDecryptKey(factory, null, key, recipientInfo, cipher.keyFactory())) 
                {
                    // указать функцию зашифрования
                    PfxEncryptor encryptor = new PfxEncryptor.PasswordWrap(this, 
                        encryptedContentInfo.contentEncryptionAlgorithm(), 
                        recipientInfo.keyDerivationAlgorithm(), 
                        recipientInfo.keyEncryptionAlgorithm(), 
                        encryptedContentInfo.contentType().value(), 
                        envelopedData.unprotectedAttrs()
                    ); 
                    // расшифровать данные
                    data = CMS.decryptData(factory, null, CEK, 
                        encryptedContentInfo, envelopedData.unprotectedAttrs()).content; 

                    // вернуть расшифрованные данные
                    return new PfxData<byte[]>(data, encryptor); 
                }
                // обработать неожидаемое исключение
                catch (InvalidKeyException e) { throw new IOException(e); }
            }
		}
		else if (encryptionType.equals(EncryptedData.class)) 
		{
			// преобразовать тип данных
			EncryptedData encryptedData = new EncryptedData(Encodable.decode(data)); 

            // извлечь зашифрованные данные
			EncryptedContentInfo encryptedContentInfo = encryptedData.encryptedContentInfo(); 
            try { 
                // указать функцию зашифрования
                PfxEncryptor encryptor = new PfxEncryptor.CipherWrap(this, 
                    encryptedContentInfo.contentEncryptionAlgorithm(), 
                    encryptedData.unprotectedAttrs(), encryptedContentInfo.contentType().value()
                ); 
                // расшифровать данные по паролю
                data = CMS.decryptData(factory, null, key, encryptedData).content; 

                // вернуть расшифрованные данные
                return new PfxData<byte[]>(data, encryptor); 
            } 
            // обработать неожидаемое исключение
            catch (InvalidKeyException e) { throw new IOException(e); }
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
