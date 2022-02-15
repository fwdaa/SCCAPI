namespace Aladdin.CAPI.KZ.GUI
{
    ///////////////////////////////////////////////////////////////////////////
    // Криптографическая культура GOST
    ///////////////////////////////////////////////////////////////////////////
    public class Culture : PBE.PBECulture
    { 
        // идентификаторы алгоритмов
        private string hashOID; private string hmacOID; private string cipherOID;
        
        // конструктор
        public Culture(PBE.PBEParameters pbeParameters, string hashOID, 

            // сохранить переданные параметры
            string hmacOID, string cipherOID) : base(pbeParameters)
        {
            // сохранить переданные параметры
            this.hashOID = hashOID; this.hmacOID = hmacOID; this.cipherOID = cipherOID;
        }
        // параметры алгоритмов
        public override ASN1.ISO.AlgorithmIdentifier HashAlgorithm(IRand rand) 
        { 
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(hashOID), ASN1.Null.Instance
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier HMacAlgorithm(IRand rand) 
        { 
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(hmacOID), ASN1.Null.Instance
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier CipherAlgorithm(IRand rand)
	    { 
    	    // сгенерировать синхропосылку
		    byte[] iv = new byte[8]; rand.Generate(iv, 0, iv.Length); 

            // указать параметры алгоритма шифрования
            ASN1.ISO.AlgorithmIdentifier cipherAlgorithm = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(cipherOID), new ASN1.OctetString(iv)
            ); 
		    // вернуть параметры алгоритма шифрования по паролю
		    return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS5.OID.pbes2), 
                new ASN1.ISO.PKCS.PKCS5.PBES2Parameter(
                    KDFAlgorithm(rand), cipherAlgorithm
                ) 
            ); 
	    } 
    }
}
