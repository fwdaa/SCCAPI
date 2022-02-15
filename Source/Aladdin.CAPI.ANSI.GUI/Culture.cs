namespace Aladdin.CAPI.ANSI.GUI
{
    ///////////////////////////////////////////////////////////////////////////
    // Криптографическая культура
    ///////////////////////////////////////////////////////////////////////////
    public static class Culture
    { 
        ///////////////////////////////////////////////////////////////////////////
        // Криптографическая культура PKCS
        ///////////////////////////////////////////////////////////////////////////
        public class PKCS : PBE.PBECulture
        {
            // идентификаторы алгоритмов
            private string hashOID; private string hmacOID; private string cipherOIDV;
        
            // конструктор
            public PKCS(PBE.PBEParameters pbeParameters, 

                // сохранить переданные параметры
                string hashOID, string hmacOID, string cipherOIDV) : base(pbeParameters)
            {
                // сохранить переданные параметры
                this.hashOID = hashOID; this.hmacOID = hmacOID; this.cipherOIDV = cipherOIDV;
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
            public override ASN1.ISO.AlgorithmIdentifier CipherAlgorithm(IRand rand)
            { 
                // указать число итераций
                int iterations = PBEParameters.PBEIterations; 

                // выделить буфер для случайных данных
                byte[] salt = new byte[PBEParameters.PBESaltLength]; 
                    
                // сгенерировать случайные данные
                rand.Generate(salt, 0, salt.Length); 

                // вернуть параметры алгоритма
                return new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(cipherOIDV), 
                    new ASN1.ISO.PKCS.PKCS5.PBEParameter(
                        new ASN1.OctetString(salt), new ASN1.Integer(iterations)
                    )                
                ); 
            }
        }
        ///////////////////////////////////////////////////////////////////////////
        // Криптографическая культура NIST
        ///////////////////////////////////////////////////////////////////////////
        public class NIST : PBE.PBECulture
        {
            // идентификаторы алгоритмов
            private string hashOID; private string hmacOID; private string cipherOID; 
        
            // конструктор
            public NIST(PBE.PBEParameters pbeParameters, 

                // сохранить переданные параметры
                string hashOID, string hmacOID, string cipherOID) : base(pbeParameters)
            {
                // сохранить переданные параметры
                this.hashOID = hashOID; this.hmacOID = hmacOID; this.cipherOID = cipherOID;
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
		    public override ASN1.ISO.AlgorithmIdentifier CipherAlgorithm(IRand rand)
		    { 
                // сгенерировать случайную синхропосылку
                byte[] iv = new byte[16]; rand.Generate(iv, 0, iv.Length); 

                // закодировать синхропосылку
                ASN1.IEncodable cipherParameters = new ASN1.OctetString(iv); 

                // при необходимости 
			    if (cipherOID == ASN1.ANSI.OID.nist_aes128_ofb ||
                    cipherOID == ASN1.ANSI.OID.nist_aes128_cfb || 
                    cipherOID == ASN1.ANSI.OID.nist_aes192_ofb || 
                    cipherOID == ASN1.ANSI.OID.nist_aes192_cfb || 
                    cipherOID == ASN1.ANSI.OID.nist_aes256_ofb || 
                    cipherOID == ASN1.ANSI.OID.nist_aes256_cfb)
                {
                    // указать дополнительные данные режима
                    cipherParameters = new ASN1.ANSI.FBParameter(
                        new ASN1.OctetString(iv), new ASN1.Integer(128)); 
                }
                // указать параметры алгоритма шифрования
                ASN1.ISO.AlgorithmIdentifier cipherAlgorithm = 
                    new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(cipherOID), cipherParameters
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
}
