package aladdin.capi.gost.keyx.gostr3410;
import aladdin.*; 
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.gost.*;
import aladdin.capi.*; 
import java.security.*;
import java.io.*;

////////////////////////////////////////////////////////////////////////////
// Согласование ключа на стороне-отправителе
////////////////////////////////////////////////////////////////////////////
public class TransportKeyWrap extends aladdin.capi.TransportKeyWrap
{
    // фабрика алгоритмов и область видимости
    private final Factory factory; private final SecurityStore scope; 
    // идентификатор алгоритма согласования ключа
    private final String transportAgreementOID;     
    
    // конструктор
    public TransportKeyWrap(Factory factory, SecurityStore scope, String transportAgreementOID) 
    {  
        // сохранить переданные параметры
        this.factory = RefObject.addRef(factory);
        this.scope   = RefObject.addRef(scope  ); 
        
        // сохранить переданные параметры
        this.transportAgreementOID = transportAgreementOID;
    }
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException   
    {
        // освободить выделенные ресурсы
        RefObject.release(scope); RefObject.release(factory); super.onClose();
    }
    // зашифровать ключ
    @Override public TransportKeyData wrap(AlgorithmIdentifier algorithmParameters, 
        IPublicKey publicKey, IRand rand, ISecretKey CEK) throws IOException, InvalidKeyException 
    {
        // преобразовать тип параметров
        aladdin.capi.gost.gostr3410.INamedParameters parameters = 
            (aladdin.capi.gost.gostr3410.INamedParameters)publicKey.parameters(); 
        
        // создать алгоритм согласования ключа (ESDH)
        try (ITransportAgreement transportAgreement = 
            createAgreementAlgorithm(factory, scope, parameters.sboxOID()))
       { 
            // зашифровать ключ
            TransportAgreementData agreementData = transportAgreement.wrap(
                null, null, new IPublicKey[] { publicKey }, rand, CEK
            ); 
            // раскодировать зашифрованный ключ
            EncryptedKey sessionEncryptedKey = new EncryptedKey(
                Encodable.decode(agreementData.encryptedKeys[0])
            ); 
            // закодировать параметры и содержимое ключа 
            aladdin.asn1.iso.pkix.SubjectPublicKeyInfo ephemeralPublicKey = 
                agreementData.publicKey.encoded(); 
                
            // закодировать параметры транспортировки
            GOSTR3410TransportParameters transportParameters = new GOSTR3410TransportParameters(
                new ObjectIdentifier(parameters.sboxOID()), 
                ephemeralPublicKey, new OctetString(agreementData.random)
            ); 
            // закодировать зашифрованный ключ с параметрами
            GOSTR3410KeyTransport encodedEncryptedKey = new GOSTR3410KeyTransport(
                sessionEncryptedKey, transportParameters
            );
            // вернуть параметры обмена ключа и зашифрованный ключ
            return new TransportKeyData(
                ephemeralPublicKey.algorithm(), encodedEncryptedKey.encoded()
            ); 
        }
    }
    protected ITransportAgreement createAgreementAlgorithm(
        Factory factory, SecurityStore scope, String sboxOID) throws IOException
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
        try (ITransportAgreement transportAgreement = (ITransportAgreement)
            factory.createAlgorithm(
                scope, transportParameters, ITransportAgreement.class))
        {
            // проверить поддержку алгоритмов
            if (transportAgreement == null) throw new UnsupportedOperationException(); 
        
            // для алгоритма ESDH
            if (transportAgreement instanceof aladdin.capi.keyx.ESDH) 
            {
                // вернуть алгоритм
                return RefObject.addRef(transportAgreement); 
            }
            // создать алгоритм ESDH
            return new aladdin.capi.keyx.ESDH(factory, transportAgreement); 
        }
    }
}
