namespace Aladdin.CAPI.GOST.Culture
{
    ///////////////////////////////////////////////////////////////////////////
    // Национальные особенности
    ///////////////////////////////////////////////////////////////////////////
    public abstract class GOST28147 : CAPI.Culture
    {
        // конструктор
        public GOST28147(string encryptionParams)

            // сохранить переданные параметры
            { this.encryptionParams = encryptionParams; } private string encryptionParams; 

	    // идентификатор набора параметров шифрования
	    protected string EncryptionParams { get { return encryptionParams; }}

        public override ASN1.ISO.AlgorithmIdentifier CipherAlgorithm(IRand rand) 
        { 
		    // сгенерировать синхропосылку
		    byte[] iv = new byte[8]; rand.Generate(iv, 0, iv.Length); 

            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.GOST.OID.gost28147_89),
                new ASN1.GOST.GOST28147CipherParameters(
				    new ASN1.OctetString(iv), 
				    new ASN1.ObjectIdentifier(EncryptionParams)
			    )
            ); 
        }
        public override ASN1.ISO.AlgorithmIdentifier KeyWrapAlgorithm(IRand rand) 
        { 
		    // сгенерировать случайные данные
		    byte[] ukm = new byte[8]; rand.Generate(ukm, 0, ukm.Length); 

            // вернуть параметры алгоритма
            return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.GOST.OID.keyWrap_cryptopro),
                new ASN1.GOST.KeyWrapParameters(
				    new ASN1.ObjectIdentifier(EncryptionParams), 
                    new ASN1.OctetString(ukm)
			    )
            ); 
        }
    }
}
