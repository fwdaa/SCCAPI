package aladdin.capi.stb.keyx.stb11762;
import aladdin.*; 
import aladdin.math.*; 
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.stb.*;
import aladdin.capi.*;
import aladdin.capi.stb.stb11762.*;
import java.security.*;
import java.math.*;
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм согласования общего ключа на принимающей стороне
///////////////////////////////////////////////////////////////////////////
public class TransportKeyUnwrap extends aladdin.capi.TransportKeyUnwrap
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 
    
    // алгоритм согласования ключа
    private final IKeyAgreement keyAgreement;       
    
    // конструктор
    public TransportKeyUnwrap(IKeyAgreement keyAgreement) 
    { 
        // сохранить переданные параметры
        this.keyAgreement = RefObject.addRef(keyAgreement); 
    }  
    // освободить используемые ресурсы
    @Override protected void onClose() throws IOException 
    {
        // освободить используемые ресурсы
        RefObject.release(keyAgreement); super.onClose();
    }
    @Override public ISecretKey unwrap(IPrivateKey privateKey, 
        TransportKeyData transportData, SecretKeyFactory keyFactory) throws IOException
    {
        // преобразовать тип параметров
        IBDHParameters bdhParameters = (IBDHParameters)privateKey.parameters(); 

        // извлечь параметры алгоритма
        int N = bdhParameters.bdhN(); BigInteger P = bdhParameters.bdhP();
            
        // проверить размер ключа
        if (N > bdhParameters.bdhL()) throw new IllegalArgumentException(); 
            
        // раскодировать переданные параметры
        BDHKeyTransParams parameters = new BDHKeyTransParams(
            transportData.algorithm.parameters()
        ); 
        // указать зашифрованное значение
        byte[] eCEK = transportData.encryptedKey; 
            
        // прочитать значение нонки
        BigInteger V = parameters.va().value(); int keySize = (N + 7) / 8; 
            
        // проверить корректность данных
        if (V.signum() == 0 || V.compareTo(P) >= 0) throw new IOException();

        // закодировать значение нонки
        byte[] random = Convert.fromBigInteger(parameters.va().value(), ENDIAN); 
            
        // извлечь идентификатор таблицы подстановок
        String sboxOID = parameters.sblock().value(); 
        
        // создать алгоритм шифрования
        try (Cipher cipher = createCipher(privateKey, sboxOID))
        {                
            // выполнить согласование ключа
            try (ISecretKey KEK = keyAgreement.deriveKey(privateKey, null, random, cipher.keyFactory(), keySize))
            {
                // расшифровать данные
                byte[] CEK = cipher.decrypt(KEK, PaddingMode.NONE, eCEK, 0, eCEK.length); 
                    
                // получить алгоритм вычисления имитовставки
                try (Mac macAlgorithm = createMacAlgorithm(privateKey, sboxOID))
                {
                    // вычислить имтовставку ключа
                    byte[] check = macAlgorithm.macData(KEK, CEK, 0, CEK.length); 
                
                    // проверить совпадение имитовставок
                    if (!Arrays.equals(check, parameters.mac().value())) throw new IOException(); 
                }
                // вернуть расшифрованный ключ
                return keyFactory.create(CEK); 
            }
            // обработать неожидаемое исключение
            catch (InvalidKeyException e) { throw new RuntimeException(e); }
        }
    }
    // создать алгоритм шифрования
    protected Cipher createCipher(IPrivateKey privateKey, String sboxOID) throws IOException
    {
        // закодировать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOST28147_ECB), 
            new GOSTSBlock(new ObjectIdentifier(sboxOID))
        );
        // получить алгоритм шифрования
        Cipher cipher = (Cipher)privateKey.factory().createAlgorithm(
            privateKey.scope(), parameters, Cipher.class
        ); 
        // проверить наличие алгоритма
        if (cipher == null) throw new UnsupportedOperationException(); return cipher;
    }
    // создать алгоритм вычисления имитовставки
    protected Mac createMacAlgorithm(IPrivateKey privateKey, String sboxOID) throws IOException
    {
        // закодировать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOST28147_MAC), 
            new GOSTSBlock(new ObjectIdentifier(sboxOID))
        );
        // получить алгоритм вычисления имитовставки
        Mac macAlgorithm = (Mac)privateKey.factory().createAlgorithm(
            privateKey.scope(), parameters, Mac.class
        ); 
        // проверить наличие алгоритма
        if (macAlgorithm == null) throw new UnsupportedOperationException(); return macAlgorithm;
    }
}
