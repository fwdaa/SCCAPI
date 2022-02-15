package aladdin.capi.gost.keyx.gostr3412;
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.gost.*;
import aladdin.capi.*;
import aladdin.capi.keyx.ESDH;
import java.io.*;

////////////////////////////////////////////////////////////////////////////
// Согласование ключа KExp15 на стороне-получателе
////////////////////////////////////////////////////////////////////////////
public class KExp15KeyUnwrap extends aladdin.capi.TransportKeyUnwrap
{
    // идентификатор алгоритма согласования ключа
    private final AlgorithmIdentifier transportAgreementParameters;     
    
    // конструктор
    public KExp15KeyUnwrap(AlgorithmIdentifier transportAgreementParameters) 
    {   
        // сохранить переданные параметры
        this.transportAgreementParameters = transportAgreementParameters; 
    } 
    @Override public ISecretKey unwrap(aladdin.capi.IPrivateKey privateKey, 
        TransportKeyData transportData, SecretKeyFactory keyFactory) throws IOException
    {
        // извлечь зашифрованный ключ с параметрами
        GOSTR3410KeyTransport2015 keyTransport = new GOSTR3410KeyTransport2015(
            Encodable.decode(transportData.encryptedKey)
        ); 
        // раскодировать открытый ключ
        aladdin.capi.IPublicKey publicKey = privateKey.factory().
            decodePublicKey(keyTransport.ephemeralPublicKey()); 
        
        // создать алгоритм согласования ключа
        try (ITransportAgreement transportAgreement = createAgreementAlgorithm(privateKey))
        {
            // расшифровать ключ
            return transportAgreement.unwrap(privateKey, publicKey, 
                keyTransport.ukm().value(), keyTransport.encryptedKey().value(), keyFactory
            ); 
        }
    }
    protected ITransportAgreement createAgreementAlgorithm(
        IPrivateKey privateKey) throws IOException
    {
        // создать алгоритм согласования ключа (SSDH)
        try (ITransportAgreement transportAgreement = KExp15Agreement.createSSDH(
            privateKey.factory(), privateKey.scope(), transportAgreementParameters))
        {
            // проверить поддержку алгоритмов
            if (transportAgreement == null) throw new UnsupportedOperationException(); 
        
            // вернуть алгоритм согласования ключа (ESDH)
            return new ESDH(privateKey.factory(), transportAgreement); 
        }
    }
}
