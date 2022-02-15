namespace Aladdin.CAPI.GOST.GUI
{
    ///////////////////////////////////////////////////////////////////////////
    // Криптографическая культура GOST
    ///////////////////////////////////////////////////////////////////////////
    public class Culture : PBE.PBECulture
    { 
        // идентификаторы алгоритмов
        private string hashOID; private string hmacOID; private string encryptionOID;
        
        // конструктор
        public Culture(PBE.PBEParameters pbeParameters, string hashOID, 

            // сохранить переданные параметры
            string hmacOID, string encryptionOID) : base(pbeParameters)
        {
            // сохранить переданные параметры
            this.hashOID = hashOID; this.hmacOID = hmacOID; this.encryptionOID = encryptionOID;
        }
        // параметры алгоримтов
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
        // вернуть параметры алгоритма шифрования
        public override ASN1.ISO.AlgorithmIdentifier CipherAlgorithm(IRand rand)
	    { 
            // параметры алгоритма шифрования
            ASN1.ISO.AlgorithmIdentifier cipherAlgorithm = null; 

            // в зависимости от идентификатора
            if (encryptionOID == ASN1.GOST.OID.gostR3412_128_ctr_acpkm)
            {
		        // сгенерировать синхропосылку
		        byte[] iv = new byte[16]; rand.Generate(iv, 0, iv.Length); 

                // указать параметры алгоритма шифрования
                cipherAlgorithm = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(encryptionOID), 
                    new ASN1.GOST.GOSTR3412EncryptionParameters(new ASN1.OctetString(iv)) 
                ); 
            }
            // в зависимости от идентификатора
            else if (encryptionOID == ASN1.GOST.OID.gostR3412_64_ctr_acpkm)
            {
		        // сгенерировать синхропосылку
		        byte[] iv = new byte[8]; rand.Generate(iv, 0, iv.Length); 

                // указать параметры алгоритма шифрования
                cipherAlgorithm = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(encryptionOID), 
                    new ASN1.GOST.GOSTR3412EncryptionParameters(new ASN1.OctetString(iv)) 
                ); 
            }
            else { 
		        // сгенерировать синхропосылку
		        byte[] iv = new byte[8]; rand.Generate(iv, 0, iv.Length); 

                // указать параметры алгоритма шифрования
                cipherAlgorithm = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.GOST.OID.gost28147_89), 
                    new ASN1.GOST.GOST28147CipherParameters(
				        new ASN1.OctetString(iv), new ASN1.ObjectIdentifier(encryptionOID)
			        )
                ); 
            }
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
