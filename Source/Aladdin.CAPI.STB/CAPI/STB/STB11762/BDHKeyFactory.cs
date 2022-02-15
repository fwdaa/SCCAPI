using System; 
using System.IO; 

namespace Aladdin.CAPI.STB.STB11762
{
    ///////////////////////////////////////////////////////////////////////////
    // Параметры алгоритма обмена СТБ 1176.2
    ///////////////////////////////////////////////////////////////////////////
    public class BDHKeyFactory : KeyFactory
    {
        // конструктор
        public BDHKeyFactory(string keyOID) { this.keyOID = keyOID; }

        // идентификаторы открытых ключей
        public override string KeyOID { get { return keyOID; }} private string keyOID; 
    
	    // способ использования ключа
	    public override KeyUsage GetKeyUsage() 
        { 
            // указать способ использования ключа
            return KeyUsage.KeyEncipherment;
        }
        // закодировать параметры
        public override ASN1.IEncodable EncodeParameters(CAPI.IParameters parameters)
        {
            // указать приведение типа
            ASN1.Tag tag = ASN1.Tag.Context(1); ASN1.IEncodable encoded; 
        
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
                IBDHParameters bdhParameters = (IBDHParameters)parameters; 

                // закодировать отдельные параметры
                ASN1.Integer bdhL = new ASN1.Integer(bdhParameters.L); 
                ASN1.Integer bdhR = new ASN1.Integer(bdhParameters.R); 
                ASN1.Integer bdhP = new ASN1.Integer(bdhParameters.P); 
                ASN1.Integer bdhG = new ASN1.Integer(bdhParameters.G); 
                ASN1.Integer bdhN = new ASN1.Integer(bdhParameters.N); 

                // закодировать параметры
                encoded = new ASN1.STB.BDHParamsList(bdhL, bdhR, bdhP, bdhG, bdhN, null);   
            }
            // выполнить преобразование типа
            return ASN1.Explicit.Encode(tag, encoded); 
        }
        // раскодировать параметры
        public override CAPI.IParameters DecodeParameters(ASN1.IEncodable encodable) 
        {
            // проверить тип параметров
            if (encodable.Tag != ASN1.Tag.Context(1)) throw new InvalidDataException(); 
        
            // раскодировать параметры
            ASN1.IEncodable parameters = ASN1.Encodable.Decode(encodable.Content);
 
            // при указании идентификатора
            if (parameters.Tag == ASN1.Tag.ObjectIdentifier) 
            {
                // раскодировать идентификатор
                ASN1.ObjectIdentifier oid = new ASN1.ObjectIdentifier(parameters); 
            
                // вернуть раскодированные параметры
                return new BDHNamedParameters(oid.Value, 
                    ASN1.STB.BDHParamsList.Parameters(oid.Value)
                );
            }
            // вернуть раскодированные параметры
            else return new BDHParameters(new ASN1.STB.BDHParamsList(parameters));         
        }
        // закодировать открытый ключ
        public override ASN1.ISO.PKIX.SubjectPublicKeyInfo EncodePublicKey(IPublicKey publicKey)
        {
            // выполнить преобразование типа
            IBDHParameters parameters = (IBDHParameters)publicKey.Parameters; 
            // выполнить преобразование типа
            IBDHPublicKey bdhPublicKey = (IBDHPublicKey)publicKey; 
        
		    // закодировать параметры ключа
		    ASN1.ISO.AlgorithmIdentifier algorithm = new ASN1.ISO.AlgorithmIdentifier(
			    new ASN1.ObjectIdentifier(keyOID), EncodeParameters(parameters)
		    ); 
		    // закодировать значение ключа
		    ASN1.BitString encoded = new ASN1.BitString(new ASN1.Integer(bdhPublicKey.Y).Encoded); 
        
            // вернуть закодированное представление
            return new ASN1.ISO.PKIX.SubjectPublicKeyInfo(algorithm, encoded); 
        }
        // раскодировать открытый ключ
        public override IPublicKey DecodePublicKey(ASN1.ISO.PKIX.SubjectPublicKeyInfo encoded) 
        {
            // раскодировать параметры
            IBDHParameters parameters = (IBDHParameters)DecodeParameters(encoded.Algorithm.Parameters); 
        
		    // раскодировать значение открытого ключа
            Math.BigInteger y = new ASN1.Integer(ASN1.Encodable.Decode(encoded.SubjectPublicKey.Value)).Value; 
        
            // вернуть открытый ключ
            return new BDHPublicKey(this, parameters, y); 
        }
        // закодировать личный ключ
        public override ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo EncodePrivateKey(
            IPrivateKey privateKey, ASN1.ISO.Attributes attributes)
        {
            // выполнить преобразование типа
            IBDHParameters parameters = (IBDHParameters)privateKey.Parameters; 
            // выполнить преобразование типа
            IBDHPrivateKey bdhPrivateKey = (IBDHPrivateKey)privateKey; 
        
		    // закодировать параметры ключа
		    ASN1.ISO.AlgorithmIdentifier algorithm = new ASN1.ISO.AlgorithmIdentifier(
			    new ASN1.ObjectIdentifier(keyOID), EncodeParameters(parameters)
		    ); 
            // закодировать значение ключа
            ASN1.OctetString encoded = new ASN1.OctetString(new ASN1.Integer(bdhPrivateKey.X).Encoded);
        
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
            IBDHParameters parameters = (IBDHParameters)DecodeParameters(
                encoded.PrivateKeyAlgorithm.Parameters
            ); 
		    // раскодировать значение личного ключа
		    Math.BigInteger x = new ASN1.Integer(ASN1.Encodable.Decode(encoded.PrivateKey.Value)).Value; 
        
            // вернуть личный ключ
            return new BDHPrivateKey(factory, null, keyOID, parameters, x); 
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
            using (IBDHPrivateKey privateKey = (IBDHPrivateKey)DecodePrivateKey(factory, encoded))
            {  
                // преобразовать тип параметров
                IBDHParameters bdhParameters = (IBDHParameters)privateKey.Parameters; 

                // указать группу Монтгомери
                Math.Fp.MontGroup group = new Math.Fp.MontGroup(bdhParameters.P); 

		        // вычислить открытый ключ
		        Math.BigInteger Y = group.Power(bdhParameters.G, privateKey.X);

                // создать объект открытого ключа 
                IPublicKey publicKey = new BDHPublicKey(this, bdhParameters, Y);

                // вернуть пару ключей
                return new KeyPair(publicKey, privateKey, null); 
            }
        } 
    }
}
