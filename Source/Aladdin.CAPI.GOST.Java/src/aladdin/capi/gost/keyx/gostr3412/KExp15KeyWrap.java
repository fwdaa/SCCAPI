package aladdin.capi.gost.keyx.gostr3412;
import aladdin.*;
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.gost.*;
import aladdin.capi.*;
import aladdin.capi.keyx.*;
import java.io.*;
import java.security.*;

////////////////////////////////////////////////////////////////////////////
// Согласование ключа KExp15 на стороне-отправителе
////////////////////////////////////////////////////////////////////////////
public class KExp15KeyWrap extends aladdin.capi.TransportKeyWrap
{
    // фабрика алгоритмов и область видимости
    private final Factory factory; private final SecurityStore scope; 
    // идентификатор алгоритма согласования ключа
    private final AlgorithmIdentifier transportAgreementParameters;     
    
    // конструктор
    public KExp15KeyWrap(Factory factory, SecurityStore scope, 
        AlgorithmIdentifier transportAgreementParameters) 
    {  
        // сохранить переданные параметры
        this.factory = RefObject.addRef(factory);
        this.scope   = RefObject.addRef(scope  ); 

        // сохранить переданные параметры
        this.transportAgreementParameters = transportAgreementParameters; 
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
        // создать алгоритм согласования ключа (ESDH)
        try (ITransportAgreement transportAgreement = createAgreementAlgorithm(factory, scope))
       { 
            // зашифровать ключ
            TransportAgreementData agreementData = transportAgreement.wrap(
                null, null, new IPublicKey[] { publicKey }, rand, CEK
            ); 
            // закодировать параметры и содержимое ключа 
            aladdin.asn1.iso.pkix.SubjectPublicKeyInfo ephemeralPublicKey = 
                agreementData.publicKey.encoded(); 
                
            // закодировать зашифрованный ключ с параметрами
            GOSTR3410KeyTransport2015 encodedEncryptedKey = new GOSTR3410KeyTransport2015(
                new OctetString(agreementData.encryptedKeys[0]), ephemeralPublicKey, 
                new OctetString(agreementData.random)
            );
            // вернуть параметры обмена ключа и зашифрованный ключ
            return new TransportKeyData(algorithmParameters, encodedEncryptedKey.encoded()); 
        }
    }
    protected ITransportAgreement createAgreementAlgorithm(
        Factory factory, SecurityStore scope) throws IOException
    {
        // создать алгоритм согласования ключа (SSDH)
        try (ITransportAgreement transportAgreement = KExp15Agreement.createSSDH(
            factory, scope, transportAgreementParameters))
        {
            // проверить поддержку алгоритмов
            if (transportAgreement == null) throw new UnsupportedOperationException(); 
        
            // вернуть алгоритм согласования ключа (ESDH)
            return new ESDH(factory, transportAgreement); 
        }
    }
}
