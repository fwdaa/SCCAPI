package aladdin.capi.gost.keyx.gostr3412;
import aladdin.asn1.*;
import aladdin.asn1.gost.*;
import aladdin.asn1.iso.*;
import aladdin.capi.*;
import aladdin.capi.keyx.*;
import java.io.*;

////////////////////////////////////////////////////////////////////////////
// Алгоритм согласования ключа
////////////////////////////////////////////////////////////////////////////
public class KExp15Agreement extends aladdin.capi.TransportAgreement
{
    // создать алгоритм SSDH
    public static TransportAgreement createSSDH(Factory factory, 
        SecurityStore scope, AlgorithmIdentifier parameters) throws IOException
    {
        // определить идентификатор алгоритма
        String oid = parameters.algorithm().value(); int blockSize = 0; 
        
        // указать идентификатор алгоритма шифрования
        if (oid.equals(OID.GOSTR3412_64_WRAP_KEXP15 )) blockSize =  8; else 
        if (oid.equals(OID.GOSTR3412_128_WRAP_KEXP15)) blockSize = 16; 
        
        // при ошибке выбросить исключение
        else throw new UnsupportedOperationException();
        
        // указать нулевую синхропосылку
        byte[] iv = new byte[blockSize / 2]; 
        
        // создать алгоритм шифрования ключа
        try (KeyWrap keyWrap = aladdin.capi.gost.wrap.KExp15.create(factory, scope, oid, iv))
        {
            // проверить поддержку алгоритма
            if (keyWrap == null) return null;  
        }
        // определить идентификатор алгоритма
        oid = new GOSTR3410KEGParameters(parameters.parameters()).algorithm().value(); 
        
        // в зависимости от идентификатора алгоритма
        if (oid.equals(OID.GOSTR3410_2012_DH_256))
        {
            // указать параметры алгоритма HMAC
            AlgorithmIdentifier hmacPrameters = new AlgorithmIdentifier(
                new ObjectIdentifier(OID.GOSTR3411_2012_HMAC_256), Null.INSTANCE
            ); 
            // создать алгоритм вычисления имитовставки
            try (Mac macAlgorithm = (Mac)factory.createAlgorithm(
                scope, hmacPrameters, Mac.class))
            {
                // проверить наличие алгоритма
                if (macAlgorithm == null) return null; 
            }
        }
        // в зависимости от идентификатора алгоритма
        else if (!oid.equals(OID.GOSTR3410_2012_DH_512)) return null; 
        
        // создать алгоритм шифрования ключа
        return new KExp15Agreement(parameters); 
    }
    // конструктор
    public KExp15Agreement(AlgorithmIdentifier parameters) { super(parameters); } 
    
    // получить алгоритм согласования ключа
    @Override protected KeyAgreement createKeyAgreementAlgorithm(
        Factory factory, SecurityStore scope, AlgorithmIdentifier parameters) throws IOException
    {
        // определить идентификатор алгоритма
        String oid = new GOSTR3410KEGParameters(parameters.parameters()).algorithm().value(); 
        
        // в зависимости от идентификатора алгоритма
        if (oid.equals(OID.GOSTR3410_2012_DH_256))
        {
            // указать параметры алгоритма HMAC
            AlgorithmIdentifier hmacPrameters = new AlgorithmIdentifier(
                new ObjectIdentifier(OID.GOSTR3411_2012_HMAC_256), Null.INSTANCE
            ); 
            // создать алгоритм вычисления имитовставки
            try (Mac macAlgorithm = (Mac)factory.createAlgorithm(
                scope, hmacPrameters, Mac.class))
            {
                // проверить наличие алгоритма
                if (macAlgorithm == null) throw new UnsupportedOperationException(); 
                        
                // создать алгоритм
                return new KEG2012_256(macAlgorithm); 
            }
        }
        // в зависимости от идентификатора алгоритма создать алгоритм
        if (oid.equals(OID.GOSTR3410_2012_DH_512)) return new KEG2012_512();
        
        // при ошибке выбросить исключение
        throw new UnsupportedOperationException();
    }
    // получить алгоритм шифрования ключа
    @Override protected KeyWrap createKeyWrapAlgorithm(Factory factory, 
        SecurityStore scope, AlgorithmIdentifier parameters, byte[] random) throws IOException
    {
        // определить идентификатор алгоритма
        String oid = parameters.algorithm().value(); int blockSize = 0; 
        
        // указать идентификатор алгоритма шифрования
        if (oid.equals(OID.GOSTR3412_64_WRAP_KEXP15 )) blockSize =  8; else 
        if (oid.equals(OID.GOSTR3412_128_WRAP_KEXP15)) blockSize = 16; 
        
        // при ошибке выбросить исключение
        else throw new UnsupportedOperationException();
        
        // извлечь синхропосылку
        byte[] iv = new byte[blockSize / 2]; System.arraycopy(random, 24, iv, 0, iv.length);
        
        // создать алгоритм шифрования ключа
        KeyWrap keyWrap = aladdin.capi.gost.wrap.KExp15.create(factory, scope, oid, iv); 
        
        // проверить наличие алгоритма
        if (keyWrap == null) throw new UnsupportedOperationException(); return keyWrap; 
    }
}