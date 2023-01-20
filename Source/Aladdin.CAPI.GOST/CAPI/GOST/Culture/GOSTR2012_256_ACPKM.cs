namespace Aladdin.CAPI.GOST.Culture
{
    ///////////////////////////////////////////////////////////////////////////
    // Национальные особенности ГОСТ R34.10-2012 (Magma/Kuznechik + ACPKM)
    ///////////////////////////////////////////////////////////////////////////
    public class GOSTR2012_256_ACPKM : CAPI.Culture
    {
        // конструктор
        public GOSTR2012_256_ACPKM() : this(8) {}

        // конструктор
        public GOSTR2012_256_ACPKM(int blockSize) 
            
            // сохранить переданные параметры
            { this.blockSize = blockSize; } private int blockSize; 

        // параметры алгоритмов
        public override ASN1.ISO.AlgorithmIdentifier HashAlgorithm(IRand rand) 
        { 
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_256),
                ASN1.Null.Instance
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier CipherAlgorithm(IRand rand) 
        { 
            if (blockSize == 8)
            { 
		        // сгенерировать синхропосылку 
		        byte[] iv = new byte[12]; rand.Generate(iv, 0, iv.Length); 

                // вернуть параметры алгоритма
                return new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3412_64_ctr_acpkm),
                    new ASN1.GOST.GOSTR3412EncryptionParameters(
				        new ASN1.OctetString(iv) 
			        )
                ); 
            }
            else { 
		        // сгенерировать синхропосылку 
		        byte[] iv = new byte[16]; rand.Generate(iv, 0, iv.Length); 

                // вернуть параметры алгоритма
                return new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3412_128_ctr_acpkm),
                    new ASN1.GOST.GOSTR3412EncryptionParameters(
				        new ASN1.OctetString(iv) 
			        )
                ); 
            }
        }
        public override ASN1.ISO.AlgorithmIdentifier SignHashAlgorithm(IRand rand) 
        { 
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3410_2012_256),
                ASN1.Null.Instance
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier SignDataAlgorithm(IRand rand) 
        {
            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_R3410_2012_256), null
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier TransportKeyAlgorithm(IRand rand) 
        { 
            // указать идентификатор алгоритма
            string oid = (blockSize == 8) ? ASN1.GOST.OID.gostR3412_64_wrap_kexp15 : 
                ASN1.GOST.OID.gostR3412_128_wrap_kexp15; 

            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(oid),
                new ASN1.GOST.GOSTR3410KEGParameters(
				    new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3410_2012_DH_256) 
		        )
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier TransportAgreementAlgorithm(IRand rand) 
        { 
            // указать идентификатор алгоритма
            string oid = (blockSize == 8) ? ASN1.GOST.OID.gostR3412_64_wrap_kexp15 : 
                ASN1.GOST.OID.gostR3412_128_wrap_kexp15; 

            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(oid),
                new ASN1.GOST.GOSTR3410KEGParameters(
				    new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3410_2012_DH_256) 
		        )
            ); 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Парольная защита
        ///////////////////////////////////////////////////////////////////////////
        public class PKCS12 : PBE.PBEDefaultCulture
        {
            // конструктор
            public PKCS12(PBE.PBEParameters parameters) 
                
                // сохранить переданные параметры
                : base(new GOSTR2012_256_ACPKM(), parameters, true) {} 
        }
    }
}

