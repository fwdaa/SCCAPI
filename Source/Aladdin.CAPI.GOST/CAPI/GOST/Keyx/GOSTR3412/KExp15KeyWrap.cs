using System;

namespace Aladdin.CAPI.GOST.Keyx.GOSTR3412
{
    ////////////////////////////////////////////////////////////////////////////
    // Согласование ключа KExp15 на стороне-отправителе
    ////////////////////////////////////////////////////////////////////////////
    public class KExp15KeyWrap : CAPI.TransportKeyWrap
    {
        // фабрика алгоритмов и область видимости
        private CAPI.Factory factory; private SecurityStore scope; 
        // идентификатор алгоритма согласования ключа
        private ASN1.ISO.AlgorithmIdentifier transportAgreementParameters;     
    
        // конструктор
        public KExp15KeyWrap(CAPI.Factory factory, SecurityStore scope, 
            ASN1.ISO.AlgorithmIdentifier transportAgreementParameters) 
        {  
            // сохранить переданные параметры
            this.factory = RefObject.AddRef(factory);
            this.scope   = RefObject.AddRef(scope  ); 

            // сохранить переданные параметры
            this.transportAgreementParameters = transportAgreementParameters; 
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
            IPublicKey publicKey, IRand rand, ISecretKey CEK)
        {
            // создать алгоритм согласования ключа (ESDH)
            using (ITransportAgreement transportAgreement = CreateAgreementAlgorithm(factory, scope))
           { 
                // зашифровать ключ
                TransportAgreementData agreementData = transportAgreement.Wrap(
                    null, null, new IPublicKey[] { publicKey }, rand, CEK
                ); 
                // закодировать параметры и содержимое ключа 
                ASN1.ISO.PKIX.SubjectPublicKeyInfo ephemeralPublicKey = 
                    agreementData.PublicKey.Encoded; 
                
                // закодировать зашифрованный ключ с параметрами
                ASN1.GOST.GOSTR3410KeyTransport2015 encodedEncryptedKey = 
                    new ASN1.GOST.GOSTR3410KeyTransport2015(
                        new ASN1.OctetString(agreementData.EncryptedKeys[0]), ephemeralPublicKey, 
                        new ASN1.OctetString(agreementData.Random)
                );
                // вернуть параметры обмена ключа и зашифрованный ключ
                return new TransportKeyData(algorithmParameters, encodedEncryptedKey.Encoded); 
            }
        }
        protected virtual ITransportAgreement CreateAgreementAlgorithm(
            CAPI.Factory factory, SecurityStore scope)
        {
            // создать алгоритм SSDH
            using (ITransportAgreement transportAgreement = 
                KExp15Agreement.CreateSSDH(factory, scope, transportAgreementParameters))
            {
                // проверить наличие алгоритма
                if (transportAgreement == null) throw new NotSupportedException(); 

                // вернуть алгоритм ESDH
                return new CAPI.Keyx.ESDH(factory, transportAgreement); 
            }
        }
    }
}
