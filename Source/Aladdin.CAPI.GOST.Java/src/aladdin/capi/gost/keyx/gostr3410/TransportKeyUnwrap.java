package aladdin.capi.gost.keyx.gostr3410;
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.gost.*;
import aladdin.capi.*; 
import java.io.*;

////////////////////////////////////////////////////////////////////////////
// Согласование ключа на стороне-получателе
////////////////////////////////////////////////////////////////////////////
public class TransportKeyUnwrap extends aladdin.capi.TransportKeyUnwrap
{
    // идентификатор алгоритма согласования ключа
    private final String transportAgreementOID;     
    
    // конструктор
    public TransportKeyUnwrap(String transportAgreementOID) 
    {   
        // сохранить переданные параметры
        this.transportAgreementOID = transportAgreementOID; 
    } 
    @Override public ISecretKey unwrap(aladdin.capi.IPrivateKey privateKey, 
        TransportKeyData transportData, SecretKeyFactory keyFactory) throws IOException
    {
        // преобразовать тип параметров
        aladdin.capi.gost.gostr3410.INamedParameters parameters = 
            (aladdin.capi.gost.gostr3410.INamedParameters)privateKey.parameters(); 
            
        // извлечь зашифрованный ключ с параметрами
        GOSTR3410KeyTransport keyTransport = new GOSTR3410KeyTransport(
            Encodable.decode(transportData.encryptedKey)
        ); 
        // извлечь параметры транспортировки
        GOSTR3410TransportParameters transportParameters = keyTransport.transportParameters(); 
            
        // извлечь идентификатор таблицы подстановок и UKM
        String sboxOID = transportParameters.encryptionParamSet().value();
        byte[] UKM     = transportParameters.ukm               ().value();
            
        // проверить идентификатор таблицы подстановок
        if (!sboxOID.equals(parameters.sboxOID())) throw new IOException(); 
            
        // раскодировать открытый ключ
        aladdin.capi.IPublicKey publicKey = privateKey.factory().decodePublicKey(
            transportParameters.ephemeralPublicKey()
        ); 
        // извлечь зашифрованный ключ и имитовставку
        EncryptedKey sessionEncryptedKey = keyTransport.sessionEncryptedKey(); 
            
        // создать алгоритм согласования ключа
        try (ITransportAgreement transportAgreement = 
            createAgreementAlgorithm(privateKey, sboxOID))
        {
            // расшифровать ключ
            return transportAgreement.unwrap(privateKey, 
                publicKey, UKM, sessionEncryptedKey.encoded(), keyFactory
            ); 
        }
    }
    protected ITransportAgreement createAgreementAlgorithm(
        IPrivateKey privateKey, String sboxOID) throws IOException
    {
        // указать идентификатор алгоритма
        AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.KEY_WRAP_CRYPTOPRO), 
            new KeyWrapParameters(new ObjectIdentifier(sboxOID), null)
        );
        // указать идентификатор алгоритма
        AlgorithmIdentifier transportParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(transportAgreementOID), wrapParameters
        ); 
        // создать алгоритм согласования ключа
        ITransportAgreement transportAgreement = (ITransportAgreement)
            privateKey.factory().createAlgorithm(
                privateKey.scope(), transportParameters, ITransportAgreement.class
        );
        // проверить поддержку алгоритмов
        if (transportAgreement == null) throw new UnsupportedOperationException();
        
        // вернуть созданный алгоритм
        return transportAgreement; 
    }
}
