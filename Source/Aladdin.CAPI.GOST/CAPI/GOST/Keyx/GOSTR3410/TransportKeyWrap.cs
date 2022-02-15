using System; 

namespace Aladdin.CAPI.GOST.Keyx.GOSTR3410
{
    ////////////////////////////////////////////////////////////////////////////
    // Согласование ключа на стороне-отправителе ГОСТ Р 34.10
    ////////////////////////////////////////////////////////////////////////////
    public class TransportKeyWrap : CAPI.TransportKeyWrap
    {
        // фабрика алгоритмов и область видимости
        private CAPI.Factory factory; private SecurityStore scope;
        // идентификатор алгоритма
        private string transportAgreementOID;     

        // конструктор
        public TransportKeyWrap(CAPI.Factory factory, SecurityStore scope, string transportAgreementOID)
        {
            // сохранить переданные параметры
            this.factory = RefObject.AddRef(factory); 
            this.scope   = RefObject.AddRef(scope  ); 
            
            // сохранить переданные параметры
            this.transportAgreementOID = transportAgreementOID; 
        }
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(scope); RefObject.Release(factory); base.OnDispose();
        }
        // зашифровать ключ
        public override TransportKeyData Wrap(
            ASN1.ISO.AlgorithmIdentifier algorithmParameters, 
            CAPI.IPublicKey publicKey, IRand rand, ISecretKey CEK)
        {
            // преобразовать тип параметров
            GOST.GOSTR3410.INamedParameters parameters =
                (GOST.GOSTR3410.INamedParameters)publicKey.Parameters;

            // создать алгоритм согласования ключа (ESDH)
            using (ITransportAgreement transportAgreement = CreateAgreementAlgorithm(
                factory, scope, parameters.SBoxOID))
            { 
                // зашифровать ключ
                TransportAgreementData agreementData = transportAgreement.Wrap(
                    null, null, new IPublicKey[] { publicKey }, rand, CEK
                ); 
                // раскодировать зашифрованный ключ
                ASN1.GOST.EncryptedKey sessionEncryptedKey =
                    new ASN1.GOST.EncryptedKey(
                        ASN1.Encodable.Decode(agreementData.EncryptedKeys[0]
                ));
                // закодировать параметры и содержимое ключа 
                ASN1.ISO.PKIX.SubjectPublicKeyInfo ephemeralPublicKey =
                    agreementData.PublicKey.Encoded;

                // закодировать параметры транспортировки
                ASN1.GOST.GOSTR3410TransportParameters transportParameters =
                    new ASN1.GOST.GOSTR3410TransportParameters(
                        new ASN1.ObjectIdentifier(parameters.SBoxOID),
                        ephemeralPublicKey, new ASN1.OctetString(agreementData.Random)
                );
                // закодировать зашифрованный ключ с параметрами
                ASN1.GOST.GOSTR3410KeyTransport encodedEncryptedKey =
                    new ASN1.GOST.GOSTR3410KeyTransport(sessionEncryptedKey, transportParameters);

                // вернуть зашифрованный ключ
                return new TransportKeyData(ephemeralPublicKey.Algorithm, encodedEncryptedKey.Encoded);
            }                    
        }
        protected virtual ITransportAgreement CreateAgreementAlgorithm(
            CAPI.Factory factory, SecurityStore scope, string sboxOID)
        {
            // указать параметры алгоритма
            ASN1.GOST.KeyWrapParameters keyWrapParameters = new ASN1.GOST.KeyWrapParameters(
                new ASN1.ObjectIdentifier(sboxOID), null
            ); 
            // указать идентификатор алгоритма
            ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.GOST.OID.keyWrap_cryptopro), keyWrapParameters
            );
            // указать идентификатор алгоритма
            ASN1.ISO.AlgorithmIdentifier transportParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(transportAgreementOID), wrapParameters
            ); 
            // создать алгоритм согласования ключа
            using (ITransportAgreement transportAgreement = 
                factory.CreateAlgorithm<ITransportAgreement>(scope, transportParameters))
            { 
                // проверить поддержку алгоритмов
                if (transportAgreement == null) throw new NotSupportedException(); 
            
                // проверить тип алгоритма
                if (transportAgreement is CAPI.Keyx.ESDH) return RefObject.AddRef(transportAgreement); 
            
                // создать алгоритм ESDH
                return new CAPI.Keyx.ESDH(factory, transportAgreement); 
            }
        }
    }
}
