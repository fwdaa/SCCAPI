package aladdin.capi.kz.keyx.tumar.gost34310;
import aladdin.*; 
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.kz.*; 
import aladdin.capi.*; 
import aladdin.util.*; 
import java.security.*;
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////////
// Алгоритм формирования общего ключа
///////////////////////////////////////////////////////////////////////////////
public class TransportAgreement extends RefObject implements ITransportAgreement 
{
    // параметры алгоритма
    private final AlgorithmIdentifier parameters; 
    
    // конструктор
    public TransportAgreement(AlgorithmIdentifier parameters) 
    { 
        // сохранить переданные параметры
        this.parameters = parameters; 
    } 
    // действия стороны-отправителя
	@Override public TransportAgreementData wrap(IPrivateKey privateKey, 
        IPublicKey publicKey, IPublicKey[] recipientPublicKeys, 
        IRand rand, ISecretKey CEK) throws IOException, InvalidKeyException
    {
        // выделить буфер требуемого размера
        byte[][] encryptedKeys = new byte[recipientPublicKeys.length][]; 
        
        // создать алгоритм согласования ключа
        try (IKeyAgreement keyAgreement = (IKeyAgreement)
            privateKey.factory().createAlgorithm(
                privateKey.scope(), parameters, IKeyAgreement.class))
        {    
            // проверить наличие алгоритма
            if (keyAgreement == null) throw new UnsupportedOperationException(); 

            // для всех получателей
            for (int i = 0; i < recipientPublicKeys.length; i++)
            { 
                // сгенерировать случайную синхропосылку
                byte[] iv = new byte[8]; rand.generate(iv, 0, iv.length);
            
                // получить алгоритм шифрования ключа
                try (KeyWrap keyWrap = getKeyWrapAlgorithm(
                    privateKey.factory(), privateKey.scope(), iv))
                {
                    // сгенерировать случайные данные
                    byte[] ukm = new byte[8]; rand.generate(ukm, 0, ukm.length); 
                    
                    // вычислить ключ шифрования ключа шифрования данных
                    try (ISecretKey KEK = keyAgreement.deriveKey(
                        privateKey, recipientPublicKeys[i], ukm, keyWrap.keyFactory(), 32))
                    {
                        // зашифровать ключ
                        byte[] wrappedCEK = keyWrap.wrap(rand, KEK, CEK); 

                        // извлечь первый блок
                        byte[] spc = Arrays.copyOf(wrappedCEK, 8); 

                        // извлечь оставшиеся данные
                        byte[] encrypted = Arrays.copyOfRange(wrappedCEK, 8, wrappedCEK.length); 

                        // закодировать зашифрованный ключ
                        EncryptedKey encryptedKey = new EncryptedKey(
                            new Integer(4), new OctetString(iv), new OctetString(spc), 
                            new OctetString(encrypted), new OctetString(ukm)
                        ); 
                        // указать заголовок данных
                        byte[] blobHeader = new byte[] { 
                            (byte)0x01, (byte)0x02, (byte)0x00, (byte)0x00, // SIMPLEBLOB
                            (byte)0x1F, (byte)0x68, (byte)0x04, (byte)0x00, // CALG_TG28147-CFB
                            (byte)0x1F, (byte)0x68, (byte)0x00, (byte)0x00, // CALG_TG28147
                        }; 
                        // объединить заголовок к зашифрованному ключу
                        encryptedKeys[i] = Array.concat(blobHeader, encryptedKey.encoded()); 
                    }
                }
            }
        }
        // вернуть зашифрованные ключи
        return new TransportAgreementData(publicKey, null, encryptedKeys); 
    }
	// действия стороны-получателя
	@Override public ISecretKey unwrap(IPrivateKey privateKey, 
        IPublicKey publicKey, byte[] random, 
        byte[] wrappedCEK, SecretKeyFactory keyFactory) throws IOException
    {
        // проверить размер данных
        if (wrappedCEK.length < 12) throw new IOException(); 

        // проверить корректность заголовка
        if (wrappedCEK[0] != 1 || wrappedCEK[1] != 2) throw new IOException();

        // раскодировать зашифрованный ключ
        EncryptedKey encryptedKey = new EncryptedKey(
            Encodable.decode(wrappedCEK, 12, wrappedCEK.length - 12)
        );
        // проверить корректность данных
        if (encryptedKey.spc().value().length != 8) throw new IOException();
 
        // объединить первый зашифрованный блок с зашифрованными данными
        wrappedCEK = Array.concat(encryptedKey.spc().value(), encryptedKey.encrypted().value()); 
        
        // извлечь синхропосылку и UKM
        byte[] iv = encryptedKey.iv().value(); byte[] ukm = encryptedKey.ukm().value(); 

        // создать алгоритм согласования ключа
        try (IKeyAgreement keyAgreement = (IKeyAgreement)
            privateKey.factory().createAlgorithm(
                privateKey.scope(), parameters, IKeyAgreement.class))
        {    
            // проверить наличие алгоритма
            if (keyAgreement == null) throw new UnsupportedOperationException(); 

            // получить алгоритм шифрования ключа
            try (KeyWrap keyWrap = getKeyWrapAlgorithm(
                privateKey.factory(), privateKey.scope(), iv))
            {
                // вычислить ключ шифрования ключа шифрования данных
                try (ISecretKey KEK = keyAgreement.deriveKey(
                    privateKey, publicKey, ukm, keyWrap.keyFactory(), 32))
                {
                    // расшифровать ключ
                    return keyWrap.unwrap(KEK, wrappedCEK, keyFactory); 
                }
                // обработать неожидаемое исключение
                catch (InvalidKeyException e) { throw new RuntimeException(e); }
            }
        }
    }
    // создать алгоритм шифрования ключа
    protected KeyWrap getKeyWrapAlgorithm(
        Factory factory, SecurityStore scope, byte[] iv) throws IOException
    {
        // указать параметры алгоритма шифрования
        AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GAMMA_CIPHER_GOST_CFB), new OctetString(iv)
        ); 
        // создать алгоритм шифрования 
        try (Cipher cipher = (Cipher)factory.createAlgorithm(
            scope, cipherParameters, Cipher.class))
        {
            // проверить наличие алгоритма
            if (cipher == null) throw new UnsupportedOperationException(); 
            
            // создать алгоритм шифрования ключа
            return new aladdin.capi.kz.wrap.KeyWrap(cipher, null); 
        }
    }
}
