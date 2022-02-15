package aladdin.capi.pkcs12;
import aladdin.asn1.*;
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*;
import aladdin.asn1.iso.pkcs.*;
import aladdin.asn1.iso.pkcs.pkcs7.*;
import aladdin.asn1.iso.pkcs.pkcs8.*;
import aladdin.asn1.iso.pkcs.pkcs12.*;
import aladdin.capi.*;
import aladdin.capi.SecretKey;
import aladdin.capi.Certificate;
import aladdin.capi.pbe.*;
import java.security.*;
import java.io.*;
import java.util.*;

public final class Pfx 
{
	///////////////////////////////////////////////////////////////////////
    // Создать контейнер
	///////////////////////////////////////////////////////////////////////
    public static PFX createContainer( 
        Factory factory, AuthenticatedSafe authenticatedSafe) throws IOException
    { 
        // указать идентификатор данных
        String dataType = aladdin.asn1.iso.pkcs.pkcs7.OID.DATA; 
        
		// закодировать данные
		byte[] encoded = authenticatedSafe.encoded();  

        // закодировать данные
        ContentInfo contentInfo = new ContentInfo(
            new ObjectIdentifier(dataType), new OctetString(encoded)
        ); 
        // закодировать контейнер
        return new PFX(new Integer(3), contentInfo, null); 
    }
	///////////////////////////////////////////////////////////////////////
	// Создать подписанный контейнер PKCS12
	///////////////////////////////////////////////////////////////////////
	public static PFX createSignedContainer(Factory factory, IRand rand,  
        Integer version, AuthenticatedSafe authenticatedSafe, 
		IPrivateKey privateKey, Certificate certificate, 
		AlgorithmIdentifier hashParameters, 
		AlgorithmIdentifier signParameters, 
		Attributes authAttributes, Attributes unauthAttributes, 
		CertificateSet certificates, RevocationInfoChoices crls) throws IOException
	{
		// указать тип данных
		String dataType = aladdin.asn1.iso.pkcs.pkcs7.OID.DATA; 

		// указать алгоритмы хэширования
		AlgorithmIdentifiers digestAlgorithms = new AlgorithmIdentifiers(
            new AlgorithmIdentifier[] {hashParameters}
        ); 
        // создать вложенные данные
		EncapsulatedContentInfo encapContentInfo = 
			new EncapsulatedContentInfo(
				new ObjectIdentifier(dataType), 
                new OctetString(authenticatedSafe.encoded())
		); 
		// подписать данные
		SignerInfo signerInfo = CMS.signData(rand, 
			privateKey, certificate, hashParameters, signParameters, 
            encapContentInfo, authAttributes, unauthAttributes
		); 
		// закодировать зашифрованные данные
		SignerInfos signerInfos = new SignerInfos(new SignerInfo[] {signerInfo});
        
		// закодировать структуру CMS
		SignedData signedData = new SignedData(version, 
			digestAlgorithms, encapContentInfo, certificates, crls, signerInfos
		);
        // указать идентификатор данных
        String oid = aladdin.asn1.iso.pkcs.pkcs7.OID.SIGNED_DATA; 
        
		// закодировать данные
		ContentInfo contentInfo = new ContentInfo(
                new ObjectIdentifier(oid), signedData
		); 
        // закодировать контейнер
		return new PFX(new Integer(3), contentInfo, null); 
	}
	///////////////////////////////////////////////////////////////////////
	// Создать контейнер PKCS12 с вычисленной имитовставкой
	///////////////////////////////////////////////////////////////////////
	public static PFX createAuthenticatedContainer(Factory factory, 
        AuthenticatedSafe authenticatedSafe, AlgorithmIdentifier hashParameters, 
        byte[] salt, int iterations, String password) throws IOException
	{
        // закодировать данные
        byte[] encoded = authenticatedSafe.encoded();  

		// создать алгоритм хэширования 
		try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(null, hashParameters, Hash.class))
        {
            // при ошибке выбросить исключение
            if (hashAlgorithm == null) throw new UnsupportedOperationException(); 

            // создать алгоритм вычисления имитовставки
            try (Mac macAlgorithm = new PBMACP12(hashAlgorithm, salt, iterations)) 
            {
                // закодировать пароль
                try (ISecretKey encodedPassword = SecretKey.fromPassword(password, "UTF-8")) 
                {
                    // вычислить имитовставку от данных
                    OctetString mac = new OctetString(macAlgorithm.macData(
                        encodedPassword, encoded, 0, encoded.length
                    )); 
                    // закодировать имитовставку от данных
                    DigestInfo digestInfo = new DigestInfo(hashParameters, mac); 

                    // закодировать информацию об имитовставке
                    MacData macData = new MacData(digestInfo, 
                        new OctetString(salt), new Integer(iterations)
                    ); 
                    // указать идентификатор данных
                    String oid = aladdin.asn1.iso.pkcs.pkcs7.OID.DATA; 

                    // закодировать данные
                    ContentInfo contentInfo = new ContentInfo(
                        new ObjectIdentifier(oid), new OctetString(encoded)
                    ); 
                    // закодировать контейнер
                    return new PFX(new Integer(3), contentInfo, macData); 
                }
                // обработать неожидаемое исключение
                catch (InvalidKeyException e) { throw new RuntimeException(e); }
            }
        }
    }
	///////////////////////////////////////////////////////////////////////
	// Проверить корректность контейнера PKCS12
	///////////////////////////////////////////////////////////////////////
	public static void checkAuthenticatedContainer(Factory factory, 
        PFX container, String password) throws IOException
    {
		// получить закодированную имитовставку
		MacData macData = container.macData(); byte[] salt = macData.macSalt().value(); 

		// получить число итераций
		int iterations = macData.iterations().value().intValue(); 

        // получить имитовставку
        byte[] mac = macData.mac().digest().value(); 
        
        // получить проверяемые данные
        AuthenticatedSafe authenticatedSafe = container.getAuthSafeContent(); 

		// закодировать данные
		byte[] encoded = authenticatedSafe.encoded();  
        
		// создать алгоритм хэширования 
		try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(null, macData.mac().digestAlgorithm(), Hash.class))
        {
            // при ошибке выбросить исключение
            if (hashAlgorithm == null) throw new UnsupportedOperationException(); 

            // создать алгоритм вычисления имитовставки
            try (Mac macAlgorithm = new PBMACP12(hashAlgorithm, salt, iterations)) 
            {
                // закодировать пароль
                try (ISecretKey encodedPassword = SecretKey.fromPassword(password, "UTF-8")) 
                {
                    // вычислить имитовставку от данных
                    byte[] check = macAlgorithm.macData(encodedPassword, encoded, 0, encoded.length);

                    // проверить совпадение имитовставок
                    if (!Arrays.equals(check, mac)) 
                    {
                        // создать алгоритм вычисления имитовставки
                        try (Mac macAlgorithm2 = new PBMACTС26(hashAlgorithm, salt, iterations)) 
                        {
                            // вычислить имитовставку от данных
                            check = macAlgorithm2.macData(encodedPassword, encoded, 0, encoded.length);
                        }
                    }
                    // проверить совпадение имитовставок
                    if (!Arrays.equals(check, mac)) throw new AuthenticationException();
                }
                // обработать неожидаемое исключение
                catch (InvalidKeyException e) { throw new RuntimeException(e); }
            }
        }
    }
	///////////////////////////////////////////////////////////////////////
	// Зашифровать элемент 
	///////////////////////////////////////////////////////////////////////
	static SafeBag encrypt(PfxData<SafeBag> safeBag) throws IOException
	{
		// проверить наличие шифрования
		if (safeBag.encryptor == null) return safeBag.content; 

		// в зависимости от типа
		if (safeBag.content.bagId().value().equals(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_KEY))
		{
			// раскодировать тип данных
			PrivateKeyInfo keyInfo = new PrivateKeyInfo(safeBag.content.bagValue());

			// зашифровать данные
			IEncodable encodable = Encodable.decode(
                safeBag.encryptor.encrypt(keyInfo.encoded())
            ); 
			// преобразовать тип данных
			EncryptedPrivateKeyInfo encryptedKey = new EncryptedPrivateKeyInfo(encodable);

			// вернуть зашифрованное представление
			return new SafeBag(
                new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_SHROUNDED_KEY), 
                encryptedKey, safeBag.content.bagAttributes()
            );
		}
		else return safeBag.content; 
	}
	///////////////////////////////////////////////////////////////////////
	// Расшифровать элемент
	///////////////////////////////////////////////////////////////////////
	static PfxData<SafeBag> decrypt(SafeBag safeBag, PfxDecryptor decryptor) throws IOException
	{
		// для незашифрованного элемента
		if (!safeBag.bagId().value().equals(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_SHROUNDED_KEY))
		{
			// вернуть исходное содержимое
			return new PfxData<SafeBag>(safeBag, null);
		}
		// расшифровать данные
		PfxData<byte[]> decrypted = decryptor.decrypt(
            safeBag.bagValue().encoded(), EncryptedPrivateKeyInfo.class
        );
		// преобразовать тип данных 
		PrivateKeyInfo keyInfo = new PrivateKeyInfo(Encodable.decode(decrypted.content));

        // вернуть расшифрованные данные
		safeBag = new SafeBag(
            new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_KEY), 
            keyInfo, safeBag.bagAttributes()
        );
        // вернуть расшифрованные данные
        return new PfxData<SafeBag>(safeBag, decrypted.encryptor); 
	}
}
