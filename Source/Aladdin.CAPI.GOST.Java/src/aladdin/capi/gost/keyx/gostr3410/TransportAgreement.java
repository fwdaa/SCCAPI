package aladdin.capi.gost.keyx.gostr3410;
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.gost.*;
import aladdin.capi.*; 
import aladdin.util.*; 
import java.io.*;

////////////////////////////////////////////////////////////////////////////
// Алгоритм согласования ключа
////////////////////////////////////////////////////////////////////////////
public class TransportAgreement extends aladdin.capi.TransportAgreement
{
    // создать алгоритм SSDH
    public static TransportAgreement createSSDH(Factory factory, 
        SecurityStore scope, AlgorithmIdentifier parameters) throws IOException
    {
        // раскодировать параметры
        AlgorithmIdentifier wrapParameters = 
            new AlgorithmIdentifier(parameters.parameters()); 

        // извлечь идентификатор алгоритма шифрования ключа
        String wrapOID = wrapParameters.algorithm().value();
        
        // раскодировать параметры
        KeyWrapParameters keyWrapParameters = new KeyWrapParameters(
            wrapParameters.parameters()        
        ); 
        // извлечь идентификатор таблицы подстановок
        String sboxOID = keyWrapParameters.paramSet().value();

        // указать параметры алгоритма
        keyWrapParameters = new KeyWrapParameters(
            new ObjectIdentifier(sboxOID), new OctetString(new byte[8])
        ); 
        // указать идентификатор алгоритма
        wrapParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(wrapOID), keyWrapParameters
        );
        // создать алгоритм шифрования ключа
        try (IAlgorithm keyWrap = factory.createAlgorithm(
            scope, wrapParameters, KeyWrap.class))
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
    public TransportAgreement(AlgorithmIdentifier parameters) { super(parameters); } 
    
    // закодировать зашифрованный ключ
    @Override protected byte[] encodeEncryptedKey(byte[] encryptedKey) 
    { 
        // выделить память для зашифрованного ключа и имитовставки
        byte[] encryptedCEK = new byte[encryptedKey.length - 4]; byte[] macCEK = new byte[4]; 

        // извлечь зашифрованный ключ
        System.arraycopy(encryptedKey, 0, encryptedCEK, 0, encryptedCEK.length);  

        // извлечь имитовставку
        System.arraycopy(encryptedKey, encryptedCEK.length, macCEK, 0, macCEK.length);  

        // закодировать зашифрованный ключ
        EncryptedKey encoded = new EncryptedKey(
            new OctetString(encryptedCEK), null, new OctetString(macCEK)
        );
        // сохранить зашифрованный ключ
        return encoded.encoded(); 
    }    
    // раскодировать зашифрованный ключ
    @Override protected byte[] decodeEncryptedKey(byte[] encryptedKey) throws IOException
    { 
        // извлечь зашифрованный ключ и имитовставку
        EncryptedKey encoded = new EncryptedKey(Encodable.decode(encryptedKey)); 

        // извлечь зашифрованный ключ и имитовставку
        byte[] encryptedCEK = encoded.encrypted().value(); 
        byte[] macCEK       = encoded.macKey   ().value();

        // создать структуру зашифрованного ключа
        return Array.concat(encryptedCEK, macCEK); 
    }    
    // получить алгоритм шифрования ключа
    @Override protected KeyWrap createKeyWrapAlgorithm(Factory factory, 
        SecurityStore scope, AlgorithmIdentifier parameters, byte[] ukm) throws IOException
    {
        // раскодировать параметры
        AlgorithmIdentifier wrapParameters = 
            new AlgorithmIdentifier(parameters.parameters()); 

        // извлечь идентификатор алгоритма шифрования ключа
        String keyWrapOID = wrapParameters.algorithm().value();
        
        // раскодировать параметры
        KeyWrapParameters keyWrapParameters = new KeyWrapParameters(
            wrapParameters.parameters()        
        ); 
        // извлечь идентификатор таблицы подстановок
        String sboxOID = keyWrapParameters.paramSet().value();

        // указать параметры алгоритма
        keyWrapParameters = new KeyWrapParameters(
            new ObjectIdentifier(sboxOID), new OctetString(ukm)
        ); 
        // указать идентификатор алгоритма
        wrapParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(keyWrapOID), keyWrapParameters
        );
        // получить алгоритм шифрования ключа
        KeyWrap algorithm = (KeyWrap)factory.createAlgorithm(
            scope, wrapParameters, KeyWrap.class
        ); 
        // проверить наличие алгоритма
        if (algorithm == null) throw new UnsupportedOperationException(); return algorithm; 
    }
}
