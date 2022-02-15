using System; 
using System.IO; 

namespace Aladdin.CAPI.STB.STB11762
{
    ///////////////////////////////////////////////////////////////////////////
    // Параметры алгоритма подписи и обмена СТБ 1176.2
    ///////////////////////////////////////////////////////////////////////////
    public class BDSBDHKeyFactory : KeyFactory
    {
        // конструктор
        public BDSBDHKeyFactory(string keyOID) { this.keyOID = keyOID; }

        // идентификаторы открытых ключей
        public override string KeyOID { get { return keyOID; }} private string keyOID; 

	    // способ использования ключа
	    public override KeyUsage GetKeyUsage() 
        { 
            // указать способ использования ключа
            return KeyUsage.DigitalSignature | KeyUsage.CertificateSignature | 
                   KeyUsage.CrlSignature     | KeyUsage.NonRepudiation       | 
                   KeyUsage.KeyEncipherment; 
        }
        // закодировать параметры
        public override ASN1.IEncodable EncodeParameters(CAPI.IParameters parameters)
        {
            // указать приведение типа
            ASN1.Tag tag = ASN1.Tag.Context(2); ASN1.IEncodable encoded; 
        
            // для именованных параметров
            if (parameters is INamedParameters) 
            { 
                // извлечь значение идентификатора
                string oid = ((INamedParameters)parameters).Oid; 
            
                // закодировать идентификатор
                encoded = new ASN1.ObjectIdentifier(oid); 

                // выполнить преобразование типа
                return ASN1.Explicit.Encode(ASN1.Tag.Context(2), encoded); 
            }
            else { 
                // преобразовать тип параметров
                IBDSParameters bdsParameters = (IBDSBDHParameters)parameters; 
                IBDHParameters bdhParameters = (IBDSBDHParameters)parameters; 

                // закодировать отдельные параметры
                ASN1.Integer     bdsL = new ASN1.Integer    (bdsParameters.L); 
                ASN1.Integer     bdsR = new ASN1.Integer    (bdsParameters.R); 
                ASN1.Integer     bdsP = new ASN1.Integer    (bdsParameters.P); 
                ASN1.Integer     bdsQ = new ASN1.Integer    (bdsParameters.Q); 
                ASN1.Integer     bdsA = new ASN1.Integer    (bdsParameters.G); 
                ASN1.OctetString bdsH = new ASN1.OctetString(bdsParameters.H);  

                // закодировать отдельные параметры
                ASN1.Integer bdhL = new ASN1.Integer(bdhParameters.L); 
                ASN1.Integer bdhR = new ASN1.Integer(bdhParameters.R); 
                ASN1.Integer bdhP = new ASN1.Integer(bdhParameters.P); 
                ASN1.Integer bdhG = new ASN1.Integer(bdhParameters.G); 
                ASN1.Integer bdhN = new ASN1.Integer(bdhParameters.N); 

                // закодировать набор параметров
                ASN1.STB.BDSParamsList signList = new ASN1.STB.BDSParamsList(
                    bdsL, bdsR, bdsP, bdsQ, bdsA, bdsH, null
                );   
                // закодировать набор параметров
                ASN1.STB.BDHParamsList keyxList = new ASN1.STB.BDHParamsList(
                    bdhL, bdhR, bdhP, bdhG, bdhN, null
                );
                // объединить наборы параметров
                encoded = new ASN1.STB.BDSBDHParamsList(signList, keyxList); 
            }
            // выполнить преобразование типа
            return ASN1.Explicit.Encode(tag, encoded); 
        }
        // раскодировать параметры
        public override CAPI.IParameters DecodeParameters(ASN1.IEncodable encodable) 
        {
            // проверить тип параметров
            if (encodable.Tag != ASN1.Tag.Context(2)) throw new InvalidDataException(); 
        
            // раскодировать параметры
            ASN1.IEncodable parameters = ASN1.Encodable.Decode(encodable.Content);
 
            // при указании идентификатора
            if (parameters.Tag == ASN1.Tag.ObjectIdentifier) 
            {
                // раскодировать идентификатор
                ASN1.ObjectIdentifier oid = new ASN1.ObjectIdentifier(parameters); 
            
                // вернуть раскодированные параметры
                return new BDSBDHNamedParameters(oid.Value, 
                    ASN1.STB.BDSBDHParamsList.Parameters(oid.Value)
                );
            }
            // раскодировать параметры
            else return new BDSBDHParameters(new ASN1.STB.BDSBDHParamsList(parameters)); 
        }
        // закодировать открытый ключ
        public override ASN1.ISO.PKIX.SubjectPublicKeyInfo EncodePublicKey(IPublicKey publicKey)
        {
            // выполнить преобразование типа
            IBDSBDHParameters parameters = (IBDSBDHParameters)publicKey.Parameters; 
            // выполнить преобразование типа
            IBDSBDHPublicKey bdshPublicKey = (IBDSBDHPublicKey)publicKey; 
        
		    // закодировать параметры ключа
		    ASN1.ISO.AlgorithmIdentifier algorithm = new ASN1.ISO.AlgorithmIdentifier(
			    new ASN1.ObjectIdentifier(keyOID), EncodeParameters(parameters)
		    ); 
            // объединить значения ключей
            ASN1.STB.BDSBDHKeyValue encodedKey = new ASN1.STB.BDSBDHKeyValue(
                new ASN1.Integer(((IBDSPublicKey)bdshPublicKey).Y), 
                new ASN1.Integer(((IBDHPublicKey)bdshPublicKey).Y)
            );
            // вернуть закодированное представление
            return new ASN1.ISO.PKIX.SubjectPublicKeyInfo(
                algorithm, new ASN1.BitString(encodedKey.Encoded)
            ); 
        }
        // раскодировать открытый ключ
        public override IPublicKey DecodePublicKey(ASN1.ISO.PKIX.SubjectPublicKeyInfo encoded) 
        {
            // раскодировать параметры
            IBDSBDHParameters parameters = (IBDSBDHParameters)DecodeParameters(
                encoded.Algorithm.Parameters
            ); 
		    // раскодировать значение открытого ключа
            ASN1.STB.BDSBDHKeyValue decodedKey = new ASN1.STB.BDSBDHKeyValue(
                ASN1.Encodable.Decode(encoded.SubjectPublicKey.Value)
            ); 
            // извлечь компоненты открытого ключа
            Math.BigInteger bdsY = decodedKey.BDSKey.Value; 
            Math.BigInteger bdhY = decodedKey.BDHKey.Value;
        
            // вернуть открытый ключ
            return new BDSBDHPublicKey(this, parameters, bdsY, bdhY); 
        }
        // закодировать личный ключ
        public override ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo EncodePrivateKey(
            IPrivateKey privateKey, ASN1.ISO.Attributes attributes)
        {
            // выполнить преобразование типа
            IBDSBDHParameters parameters = (IBDSBDHParameters)privateKey.Parameters; 
            // выполнить преобразование типа
            IBDSBDHPrivateKey bdshPrivateKey = (IBDSBDHPrivateKey)privateKey; 
        
		    // закодировать параметры ключа
		    ASN1.ISO.AlgorithmIdentifier algorithm = new ASN1.ISO.AlgorithmIdentifier(
			    new ASN1.ObjectIdentifier(keyOID), EncodeParameters(parameters)
		    ); 
            // объединить значения ключей
            ASN1.STB.BDSBDHKeyValue encodedKey = new ASN1.STB.BDSBDHKeyValue(
                new ASN1.Integer(((IBDSPrivateKey)bdshPrivateKey).X), 
                new ASN1.Integer(((IBDHPrivateKey)bdshPrivateKey).X)
            ); 
            // вернуть закодированное представление
            return new ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo(new ASN1.Integer(0), 
                algorithm, new ASN1.OctetString(encodedKey.Encoded), attributes
            ); 
        }
        // раскодировать личный ключ
        public override IPrivateKey DecodePrivateKey(CAPI.Factory factory,
            ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo encoded) 
        {
            // раскодировать параметры
            IBDSBDHParameters parameters = (IBDSBDHParameters)DecodeParameters(
                encoded.PrivateKeyAlgorithm.Parameters
            ); 
		    // раскодировать значение личного ключа
            ASN1.STB.BDSBDHKeyValue keyValue = new ASN1.STB.BDSBDHKeyValue(
                ASN1.Encodable.Decode(encoded.PrivateKey.Value)
            ); 
            // извлечь компоненты личного ключа
            Math.BigInteger bdsX = keyValue.BDSKey.Value; 
            Math.BigInteger bdhX = keyValue.BDHKey.Value;
        
            // вернуть личный ключ
            return new BDSBDHPrivateKey(factory, null, keyOID, parameters, bdsX, bdhX); 
        }
        // закодировать пару ключей
        public override ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo EncodeKeyPair(
            CAPI.IPrivateKey privateKey, CAPI.IPublicKey publicKey, 
            ASN1.ISO.Attributes attributes)
        {
            // закодировать личный ключ
            return EncodePrivateKey(privateKey, attributes); 
        }
	    // раскодировать пару ключей
        public override KeyPair DecodeKeyPair(CAPI.Factory factory,  
            ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo encoded) 
        {
            // раскодировать личный ключ
            using (IBDSBDHPrivateKey privateKey = (IBDSBDHPrivateKey)DecodePrivateKey(factory, encoded))
            {  
                // преобразовать тип параметров
                IBDSParameters bdsParameters = (IBDSParameters)privateKey.Parameters; 
                IBDHParameters bdhParameters = (IBDHParameters)privateKey.Parameters; 

                // указать группу Монтгомери
                Math.Fp.MontGroup bdsGroup = new Math.Fp.MontGroup(bdsParameters.P); 
                Math.Fp.MontGroup bdhGroup = new Math.Fp.MontGroup(bdhParameters.P); 

		        // вычислить открытый ключ
		        Math.BigInteger bdsY = bdsGroup.Power(
                    bdsParameters.G, ((IBDSPrivateKey)privateKey).X
                );
		        Math.BigInteger bdhY = bdhGroup.Power(
                    bdhParameters.G, ((IBDHPrivateKey)privateKey).X
                );
                // создать объект открытого ключа 
                IPublicKey publicKey = new BDSBDHPublicKey(this, 
                    (IBDSBDHParameters)privateKey.Parameters, bdsY, bdhY
                );
                // вернуть пару ключей
                return new KeyPair(publicKey, privateKey, null); 
            }
        } 
    }
}
