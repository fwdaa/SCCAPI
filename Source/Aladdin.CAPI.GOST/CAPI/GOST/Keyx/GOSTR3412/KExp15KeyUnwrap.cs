using System;

namespace Aladdin.CAPI.GOST.Keyx.GOSTR3412
{
    ////////////////////////////////////////////////////////////////////////////
    // Согласование ключа KExp15 на стороне-получателе
    ////////////////////////////////////////////////////////////////////////////
    public class KExp15KeyUnwrap : CAPI.TransportKeyUnwrap
    {
        // идентификатор алгоритма согласования ключа
        private ASN1.ISO.AlgorithmIdentifier transportAgreementParameters;     
    
        // конструктор
        public KExp15KeyUnwrap(ASN1.ISO.AlgorithmIdentifier transportAgreementParameters) 
        {   
            // сохранить переданные параметры
            this.transportAgreementParameters = transportAgreementParameters; 
        } 
        public override ISecretKey Unwrap(IPrivateKey privateKey, 
            TransportKeyData transportData, SecretKeyFactory keyFactory)
        {
            // извлечь зашифрованный ключ с параметрами
            ASN1.GOST.GOSTR3410KeyTransport2015 keyTransport = 
                new ASN1.GOST.GOSTR3410KeyTransport2015(
                    ASN1.Encodable.Decode(transportData.EncryptedKey)
            ); 
            // раскодировать открытый ключ
            IPublicKey publicKey = privateKey.Factory.DecodePublicKey(
                keyTransport.EphemeralPublicKey
            ); 
            // создать алгоритм согласования ключа
            using (ITransportAgreement transportAgreement = CreateAgreementAlgorithm(privateKey))
            {
                // расшифровать ключ
                return transportAgreement.Unwrap(privateKey, publicKey, 
                    keyTransport.Ukm.Value, keyTransport.EncryptedKey.Value, keyFactory
                ); 
            }
        }
        protected virtual ITransportAgreement CreateAgreementAlgorithm(IPrivateKey privateKey)
        {
            // создать алгоритм SSDH
            using (ITransportAgreement transportAgreement = KExp15Agreement.CreateSSDH(
                privateKey.Factory, privateKey.Scope, transportAgreementParameters))
            {
                // проверить наличие алгоритма
                if (transportAgreement == null) throw new NotSupportedException(); 

                // вернуть алгоритм ESDH
                return new CAPI.Keyx.ESDH(privateKey.Factory, transportAgreement); 
            }
        }
    }
}
