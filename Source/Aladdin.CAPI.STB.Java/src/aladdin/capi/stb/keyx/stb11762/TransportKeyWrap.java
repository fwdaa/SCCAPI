package aladdin.capi.stb.keyx.stb11762;
import aladdin.*; 
import aladdin.math.*; 
import aladdin.asn1.*;
import aladdin.asn1.Integer;
import aladdin.asn1.iso.*;
import aladdin.asn1.stb.*;
import aladdin.capi.*;
import aladdin.capi.stb.stb11762.*;
import java.math.*;
import java.security.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм согласования общего ключа на передающей стороне
///////////////////////////////////////////////////////////////////////////
public class TransportKeyWrap extends aladdin.capi.TransportKeyWrap
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 
    
    private final Factory       factory;      // фабрика алгоритмов
    private final SecurityStore scope;        // область видимости
    private final IKeyAgreement keyAgreement; // алгоритм согласования ключа
    private final String        sboxOID;      // идентификатор таблицы подстановок
    
    // конструктор
    public TransportKeyWrap(Factory factory, SecurityStore scope, 
        IKeyAgreement keyAgreement, String sboxOID) 
    { 
        // сохранить переданные параметры
        this.factory      = RefObject.addRef(factory     ); 
        this.scope        = RefObject.addRef(scope       ); 
        this.keyAgreement = RefObject.addRef(keyAgreement); this.sboxOID = sboxOID;
    }  
    // освободить используемые ресурсы
    @Override protected void onClose() throws IOException  
    {
        // освободить используемые ресурсы
        RefObject.release(keyAgreement); RefObject.release(scope);
        
        // освободить используемые ресурсы
        RefObject.release(factory); super.onClose();
    }
    // зашифровать ключ
    @Override public TransportKeyData wrap(AlgorithmIdentifier algorithmParameters, 
        IPublicKey publicKey, IRand rand, ISecretKey CEK) throws IOException, InvalidKeyException
    {
        // преобразовать тип параметров
        IBDHParameters bdhParameters = (IBDHParameters)publicKey.parameters(); 

        // извлечь параметры алгоритма
        int L = bdhParameters.bdhL(); int N = bdhParameters.bdhN();
            
        // проверить размер ключа
        if (N > L) throw new IllegalArgumentException(); byte[] eCEK = new byte[32]; 
            
        // зашифровать ключ
        BDHKeyTransParams keyTransParameters = wrap(publicKey, rand, CEK, eCEK, (N + 7) / 8); 
        
        // указать параметры
        algorithmParameters = new AlgorithmIdentifier(
            algorithmParameters.algorithm(), keyTransParameters
        ); 
        // указать параметры алгоритма
        return new TransportKeyData(algorithmParameters, eCEK); 
    }
    // зашифровать ключ
    protected BDHKeyTransParams wrap(IPublicKey publicKey, 
        IRand rand, ISecretKey CEK, byte[] eCEK, int keySize) 
        throws IOException, InvalidKeyException
    {
        // преобразовать тип параметров
        IBDHParameters bdhParameters = (IBDHParameters)publicKey.parameters(); 

        // извлечь параметры алгоритма
        int L = bdhParameters.bdhL(); int N = bdhParameters.bdhN();
            
        // проверить размер ключа
        if (N > L) throw new IllegalArgumentException(); 
            
        // получить значение зашифровываемого ключа
        byte[] value = CEK.value(); if (value == null || value.length != 32) 
        {
            // при ошибке выбросить исключение
            throw new UnsupportedOperationException();
        } 
        // создать алгоритм шифрования
        try (Cipher cipher = createCipher(sboxOID))
        {                
            // выполнить согласование ключа
            try (DeriveData kdfData = keyAgreement.deriveKey(
                null, publicKey, rand, cipher.keyFactory(), keySize)) 
            {
                // раскодировать значение нонки
                BigInteger V = Convert.toBigInteger(kdfData.random, ENDIAN); 
                
                // зашифровать ключ 
                byte[] encrypted = cipher.encrypt(kdfData.key, PaddingMode.NONE, value, 0, value.length); 
            
                // скопировать зашифрованное значение
                System.arraycopy(encrypted, 0, eCEK, 0, encrypted.length);
            
                // получить алгоритм вычисления имитовставки
                try (Mac macAlgorithm = createMacAlgorithm(sboxOID))
                {
                    // вычислить имитовставку
                    byte[] mac = macAlgorithm.macData(kdfData.key, value, 0, value.length); 

                    // вернуть использованные параметры
                    return new BDHKeyTransParams(new Integer(V), 
                        new OctetString(mac), new ObjectIdentifier(sboxOID)
                    ); 
                }
            }
        }
    }
    // создать алгоритм шифрования
    protected Cipher createCipher(String sboxOID) throws IOException
    {
        // закодировать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOST28147_ECB), 
            new GOSTSBlock(new ObjectIdentifier(sboxOID))
        );
        // получить алгоритм шифрования
        Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class); 
        
        // проверить наличие алгоритма
        if (cipher == null) throw new UnsupportedOperationException(); return cipher;
    }
    // создать алгоритм вычисления имитовставки
    protected Mac createMacAlgorithm(String sboxOID) throws IOException
    {
        // закодировать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOST28147_MAC), 
            new GOSTSBlock(new ObjectIdentifier(sboxOID))
        );
        // получить алгоритм вычисления имитовставки
        Mac macAlgorithm = (Mac)factory.createAlgorithm(scope, parameters, Mac.class); 
        
        // проверить наличие алгоритма
        if (macAlgorithm == null) throw new UnsupportedOperationException(); return macAlgorithm;
    }
}
