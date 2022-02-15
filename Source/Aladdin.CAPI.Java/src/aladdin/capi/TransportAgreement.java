package aladdin.capi;
import aladdin.*; 
import aladdin.asn1.iso.*;
import aladdin.capi.keyx.*; 
import java.security.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм ассиметричного шифрования ключа на основе двух алгоритмов
///////////////////////////////////////////////////////////////////////////
public class TransportAgreement extends RefObject implements ITransportAgreement
{
    // параметры алгоритма
    private final AlgorithmIdentifier parameters; 
    
    // создать алгоритм SSDH
    public static TransportAgreement createSSDH(Factory factory, 
        SecurityStore scope, AlgorithmIdentifier parameters) throws IOException
    {
        // указать параметры шифрования ключа
        AlgorithmIdentifier keyWrapParameters = 
            new AlgorithmIdentifier(parameters.parameters()); 
        
        // создать алгоритм шифрования ключа
        try (IAlgorithm keyWrap = factory.createAlgorithm(
            scope, keyWrapParameters, KeyWrap.class))
        {
            // проверить поддержку алгоритма
            if (keyWrap == null) return null;  
        }
        // создать алгоритм согласования ключа
        try (IAlgorithm keyAgreement = factory.createAlgorithm(
            scope, parameters, IKeyAgreement.class))
        {
            // проверить поддержку алгоритма
            if (keyAgreement == null) return null;  
        }
        // создать алгоритм шифрования ключа
        return new TransportAgreement(parameters); 
    }
    // конструктор
    public TransportAgreement(AlgorithmIdentifier parameters) 
    { 
        // сохранить переданные параметры
        this.parameters = parameters; 
    }
    // действия стороны-отправителя
    @Override public TransportAgreementData wrap(IPrivateKey privateKey, 
        IPublicKey publicKey, IPublicKey[] recipientPublicKeys, IRand rand, ISecretKey key) 
        throws IOException, InvalidKeyException
    {
        // выделить буфер требуемого размера
        byte[][] encryptedKeys = new byte[recipientPublicKeys.length][]; 
        
        // создать алгоритм согласования ключа
        try (KeyAgreement keyAgreement = createKeyAgreementAlgorithm(
            privateKey.factory(), privateKey.scope(), parameters))
        {    
            // сгенерировать случайные данные
            byte[] random = keyAgreement.generate(publicKey.parameters(), rand); 

            // создать алгоритм шифрования ключа
            try (KeyWrap keyWrap = createKeyWrapAlgorithm(
                privateKey.factory(), privateKey.scope(), parameters, random)) 
            {
                // определить допустимые размеры ключей
                int[] keySizes = keyWrap.keySizes(); int keySize = -1; 
        
                // указать рекомендуемый размер ключа
                if (keySizes != null && keySizes.length == 1) keySize = keySizes[0]; 
        
                // для всех получателей
                for (int i = 0; i < recipientPublicKeys.length; i++)
                { 
                    // вычислить ключ шифрования ключа шифрования данных
                    try (ISecretKey KEK = keyAgreement.deriveKey(privateKey, 
                        recipientPublicKeys[i], random, keyWrap.keyFactory(), keySize)) 
                    {
                        // проверить допустимость размера ключа
                        if (!KeySizes.contains(keySizes, KEK.length())) 
                        {
                            // выбросить исключение
                            throw new IllegalStateException();
                        }
                        // зашифровать ключ
                        encryptedKeys[i] = encodeEncryptedKey(keyWrap.wrap(rand, KEK, key)); 
                    }
                }
            }
            // вернуть зашифрованные ключи
            return new TransportAgreementData(publicKey, random, encryptedKeys); 
        }
    }
    // действия стороны-получателя
    @Override public ISecretKey unwrap(IPrivateKey privateKey, IPublicKey publicKey, 
        byte[] random, byte[] encryptedKey, SecretKeyFactory keyFactory) throws IOException
    {
        // создать алгоритм согласования ключа
        try (KeyAgreement keyAgreement = createKeyAgreementAlgorithm(
            privateKey.factory(), privateKey.scope(), parameters))
        {    
            // создать алгоритм шифрования ключа
            try (KeyWrap keyWrap = createKeyWrapAlgorithm(
                privateKey.factory(), privateKey.scope(), parameters, random)) 
            {
                // определить допустимые размеры ключей
                int[] keySizes = keyWrap.keySizes(); int keySize = -1;  
        
                // указать рекомендуемый размер ключа
                if (keySizes != null && keySizes.length == 1) keySize = keySizes[0]; 
        
                // вычислить ключ шифрования ключа шифрования данных
                try (ISecretKey KEK = keyAgreement.deriveKey(privateKey, 
                    publicKey, random, keyWrap.keyFactory(), keySize)) 
                {
                    // проверить допустимость размера ключа
                    if (!KeySizes.contains(keySizes, KEK.length())) 
                    {
                        // выбросить исключение
                        throw new IllegalStateException();
                    }
                    // расшифровать ключ
                    return keyWrap.unwrap(KEK, decodeEncryptedKey(encryptedKey), keyFactory); 
                }
                // обработать неожидаемую ошибку
                catch (InvalidKeyException e) { throw new RuntimeException(e); }
            }
        }
    }
    // закодировать/раскодировать зашифрованный ключ
    protected byte[] encodeEncryptedKey(byte[] encryptedKey) throws IOException { return encryptedKey; }    
    protected byte[] decodeEncryptedKey(byte[] encryptedKey) throws IOException { return encryptedKey; }    
    
    // получить алгоритм согласования ключа
    protected KeyAgreement createKeyAgreementAlgorithm(
        Factory factory, SecurityStore scope, AlgorithmIdentifier parameters) throws IOException
    {
        // создать алгоритм согласования ключа
        KeyAgreement keyAgreement = (KeyAgreement)
            factory.createAlgorithm(scope, parameters, IKeyAgreement.class); 
            
        // проверить наличие алгоритма
        if (keyAgreement == null) throw new UnsupportedOperationException(); return keyAgreement; 
    }
    // получить алгоритм шифрования ключа
    protected KeyWrap createKeyWrapAlgorithm(Factory factory, 
        SecurityStore scope, AlgorithmIdentifier parameters, byte[] random) throws IOException
    {
        // указать параметры шифрования ключа
        AlgorithmIdentifier keyWrapParameters = new AlgorithmIdentifier(parameters.parameters()); 
        
        // создать алгоритм шифрования ключа
        KeyWrap keyWrap = (KeyWrap)factory.createAlgorithm(scope, keyWrapParameters, KeyWrap.class); 
        
        // проверить поддержку алгоритма
        if (keyWrap == null) throw new UnsupportedOperationException(); return keyWrap; 
    }
}
