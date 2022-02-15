using System; 
using System.IO; 

namespace Aladdin.CAPI.STB.STB11762
{
    ///////////////////////////////////////////////////////////////////////////
    // Параметры алгоритма подписи СТБ 1176.2
    ///////////////////////////////////////////////////////////////////////////
    public class BDSKeyFactory : KeyFactory
    {
        // конструктор
        public BDSKeyFactory(string keyOID) { this.keyOID = keyOID; }

        // идентификаторы открытых ключей
        public override string KeyOID { get { return keyOID; }} private string keyOID; 
    
	    // способ использования ключа
	    public override KeyUsage GetKeyUsage() 
        { 
            // указать способ использования ключа
            return KeyUsage.DigitalSignature | KeyUsage.CertificateSignature | 
                   KeyUsage.CrlSignature     | KeyUsage.NonRepudiation; 
        }
        // закодировать параметры
        public override ASN1.IEncodable EncodeParameters(CAPI.IParameters parameters)
        {
            // указать приведение типа
            ASN1.Tag tag = ASN1.Tag.Context(0); ASN1.IEncodable encoded; 
        
            // для именованных параметров
            if (parameters is INamedParameters) 
            { 
                // извлечь значение идентификатора
                string oid = ((INamedParameters)parameters).Oid; 
            
                // закодировать идентификатор
                encoded = new ASN1.ObjectIdentifier(oid); 
            }
            else {
                // преобразовать тип параметров
                IBDSParameters bdsParameters = (IBDSParameters)parameters; 

                // закодировать отдельные параметры
                ASN1.Integer     bdsL = new ASN1.Integer    (bdsParameters.L); 
                ASN1.Integer     bdsR = new ASN1.Integer    (bdsParameters.R); 
                ASN1.Integer     bdsP = new ASN1.Integer    (bdsParameters.P); 
                ASN1.Integer     bdsQ = new ASN1.Integer    (bdsParameters.Q); 
                ASN1.Integer     bdsA = new ASN1.Integer    (bdsParameters.G); 
                ASN1.OctetString bdsH = new ASN1.OctetString(bdsParameters.H);
            
                // закодировать параметры
                encoded = new ASN1.STB.BDSParamsList(bdsL, bdsR, bdsP, bdsQ, bdsA, bdsH, null);   
            }
            // выполнить преобразование типа
            return ASN1.Explicit.Encode(tag, encoded); 
        }
        // раскодировать параметры
        public override CAPI.IParameters DecodeParameters(ASN1.IEncodable encodable)
        {
            // проверить тип параметров
            if (encodable.Tag != ASN1.Tag.Context(0)) throw new InvalidDataException(); 
        
            // раскодировать параметры
            ASN1.IEncodable parameters = ASN1.Encodable.Decode(encodable.Content);
 
            // при указании идентификатора
            if (parameters.Tag == ASN1.Tag.ObjectIdentifier) 
            {
                // раскодировать идентификатор
                ASN1.ObjectIdentifier oid = new ASN1.ObjectIdentifier(parameters); 
            
                // вернуть раскодированные параметры
                return new BDSNamedParameters(oid.Value, 
                    ASN1.STB.BDSParamsList.Parameters(oid.Value)
                );
            }
            // вернуть раскодированные параметры
            else return new BDSParameters(new ASN1.STB.BDSParamsList(parameters)); 
        }
        // закодировать открытый ключ
        public override ASN1.ISO.PKIX.SubjectPublicKeyInfo EncodePublicKey(IPublicKey publicKey)
        {
            // выполнить преобразование типа
            IBDSParameters parameters = (IBDSParameters)publicKey.Parameters; 
            // выполнить преобразование типа
            IBDSPublicKey bdsPublicKey = (IBDSPublicKey)publicKey; 
        
		    // закодировать параметры ключа
		    ASN1.ISO.AlgorithmIdentifier algorithm = new ASN1.ISO.AlgorithmIdentifier(
			    new ASN1.ObjectIdentifier(keyOID), EncodeParameters(parameters)
		    ); 
            // закодировать значение ключа
            ASN1.BitString encoded = new ASN1.BitString(new ASN1.Integer(bdsPublicKey.Y).Encoded);

            // вернуть закодированное представление
            return new ASN1.ISO.PKIX.SubjectPublicKeyInfo(algorithm, encoded); 
        }
        // раскодировать открытый ключ
        public override IPublicKey DecodePublicKey(ASN1.ISO.PKIX.SubjectPublicKeyInfo encoded) 
        {
            // раскодировать параметры
            IBDSParameters parameters = (IBDSParameters)DecodeParameters(encoded.Algorithm.Parameters); 
        
		    // раскодировать значение открытого ключа
            Math.BigInteger y = new ASN1.Integer(ASN1.Encodable.Decode(encoded.SubjectPublicKey.Value)).Value; 
        
            // вернуть открытый ключ
            return new BDSPublicKey(this, parameters, y); 
        }
        // закодировать личный ключ
        public override ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo EncodePrivateKey(
            IPrivateKey privateKey, ASN1.ISO.Attributes attributes)
        {
            // выполнить преобразование типа
            IBDSParameters parameters = (IBDSParameters)privateKey.Parameters; 
            // выполнить преобразование типа
            IBDSPrivateKey bdsPrivateKey = (IBDSPrivateKey)privateKey; 
        
		    // закодировать параметры ключа
		    ASN1.ISO.AlgorithmIdentifier algorithm = new ASN1.ISO.AlgorithmIdentifier(
			    new ASN1.ObjectIdentifier(keyOID), EncodeParameters(parameters)
		    ); 
            // закодировать значение ключа
            ASN1.OctetString encoded = new ASN1.OctetString(new ASN1.Integer(bdsPrivateKey.X).Encoded);
        
            // вернуть закодированное представление
            return new ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo(
                new ASN1.Integer(0), algorithm, encoded, attributes
            ); 
        }
        // раскодировать личный ключ
        public override IPrivateKey DecodePrivateKey(CAPI.Factory factory,
            ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo encoded) 
        {
            // раскодировать параметры
            IBDSParameters parameters = (IBDSParameters)DecodeParameters(
                encoded.PrivateKeyAlgorithm.Parameters
            ); 
		    // раскодировать значение личного ключа
		    Math.BigInteger x = new ASN1.Integer(ASN1.Encodable.Decode(encoded.PrivateKey.Value)).Value; 
        
            // вернуть личный ключ
            return new BDSPrivateKey(factory, null, keyOID, parameters, x); 
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
            using (IBDSPrivateKey privateKey = (IBDSPrivateKey)DecodePrivateKey(factory, encoded))
            {  
                // преобразовать тип параметров
                IBDSParameters bdsParameters = (IBDSParameters)privateKey.Parameters; 

                // указать группу Монтгомери
                Math.Fp.MontGroup group = new Math.Fp.MontGroup(bdsParameters.P); 

		        // вычислить открытый ключ
		        Math.BigInteger Y = group.Power(bdsParameters.G, privateKey.X);

                // создать объект открытого ключа 
                IPublicKey publicKey = new BDSPublicKey(this, bdsParameters, Y);

                // вернуть пару ключей
                return new KeyPair(publicKey, privateKey, null); 
            }
        } 
    }
}
