using System; 
using System.IO; 

namespace Aladdin.CAPI.GOST.Keyx.GOSTR3410
{
    ////////////////////////////////////////////////////////////////////////////
    // Согласование ключа на стороне-получателе ГОСТ Р 34.10
    ////////////////////////////////////////////////////////////////////////////
    public class TransportKeyUnwrap : CAPI.TransportKeyUnwrap
    {
        // идентификатор алгоритма
        private string transportAgreementOID;     

        // конструктор
        public TransportKeyUnwrap(string transportAgreementOID) 
        {    
            // сохранить переданные параметры
            this.transportAgreementOID = transportAgreementOID; 
        } 
        public override ISecretKey Unwrap(CAPI.IPrivateKey privateKey, 
            TransportKeyData transportData, SecretKeyFactory keyFactory)
        {
            // преобразовать тип параметров
            GOST.GOSTR3410.INamedParameters parameters =
                (GOST.GOSTR3410.INamedParameters)privateKey.Parameters;

            // извлечь зашифрованный ключ с параметрами
            ASN1.GOST.GOSTR3410KeyTransport keyTransport =
                new ASN1.GOST.GOSTR3410KeyTransport(
                    ASN1.Encodable.Decode(transportData.EncryptedKey)
            );
            // извлечь параметры транспортировки
            ASN1.GOST.GOSTR3410TransportParameters transportParameters =
                keyTransport.TransportParameters;

            // извлечь идентификатор таблицы подстановок и UKM
            string sboxOID = transportParameters.EncryptionParamSet.Value;
            byte[] UKM     = transportParameters.Ukm.Value;

            // проверить идентификатор таблицы подстановок
            if (sboxOID != parameters.SBoxOID) throw new InvalidDataException();

            // раскодировать открытый ключ
            CAPI.IPublicKey publicKey = privateKey.Factory.DecodePublicKey(
                transportParameters.EphemeralPublicKey
            );
            // извлечь зашифрованный ключ и имитовставку
            ASN1.GOST.EncryptedKey sessionEncryptedKey = keyTransport.SessionEncryptedKey;

            // создать алгоритм согласования ключа
            using (ITransportAgreement transportAgreement = CreateAgreementAlgorithm(privateKey, sboxOID))
            { 
                // расшифровать ключ
                return transportAgreement.Unwrap(privateKey, publicKey, 
                    UKM, sessionEncryptedKey.Encoded, keyFactory
                );
            }
        }
        protected virtual ITransportAgreement CreateAgreementAlgorithm(IPrivateKey privateKey, string sboxOID)
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
            ITransportAgreement keyAgreement = privateKey.Factory.
                CreateAlgorithm<ITransportAgreement>(privateKey.Scope, transportParameters);

            // проверить поддержку алгоритмов
            if (keyAgreement == null) throw new NotSupportedException(); return keyAgreement; 
        }
    }
}
