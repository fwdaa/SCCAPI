using System;

namespace Aladdin.CAPI.PBE
{
    ///////////////////////////////////////////////////////////////////////////
    // Парольная защита
    ///////////////////////////////////////////////////////////////////////////
	public abstract class PBECulture
	{
        // конструктор
        public PBECulture(PBEParameters pbeParameters) 
         
            // сохранить переданные параметры
            { this.pbeParameters = pbeParameters; } private PBEParameters pbeParameters;

        // национальные особенности
        protected virtual CAPI.Culture BaseCulture { get { return null; }}

        // параметры шифрования по паролю 
        public PBEParameters PBEParameters { get { return pbeParameters; } } 

        // параметры алгоритмов
	    public virtual ASN1.ISO.AlgorithmIdentifier HashAlgorithm(IRand rand) 
	    { 
            // вернуть параметры алгоритмов
            return BaseCulture.HashAlgorithm(rand); 
	    }
	    public abstract ASN1.ISO.AlgorithmIdentifier HMacAlgorithm   (IRand rand);
	    public virtual  ASN1.ISO.AlgorithmIdentifier CipherAlgorithm (IRand rand)
	    { 
		    // закодировать параметры шифрования
		    ASN1.ISO.AlgorithmIdentifier cipherAlgorithm = BaseCulture.CipherAlgorithm(rand);

			// проверить указание алгоритма
			if (cipherAlgorithm == null) return null;

			// вернуть параметры алгоритма
			return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS5.OID.pbes2), 
                new ASN1.ISO.PKCS.PKCS5.PBES2Parameter(
                    KDFAlgorithm(rand), cipherAlgorithm
                )
            ); 
	    }
	    public virtual ASN1.ISO.AlgorithmIdentifier KDFAlgorithm(IRand rand)
	    { 
            // определить число итераций
            int iterations = pbeParameters.PBEIterations; 

		    // выделить память для salt-значения
		    byte[] salt = new byte[pbeParameters.PBESaltLength]; 
            
		    // сгенерировать salt-значение
            rand.Generate(salt, 0, salt.Length); 

	        // вернуть параметры алгоритма
	        return new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS5.OID.pbkdf2), 
                new ASN1.ISO.PKCS.PKCS5.PBKDF2Parameter(
                    new ASN1.OctetString(salt), 
                    new ASN1.Integer(iterations), null, HMacAlgorithm(rand)
			    )
            ); 
	    }
		///////////////////////////////////////////////////////////////////////
		// Зашифровать данные по паролю
		///////////////////////////////////////////////////////////////////////
		public ASN1.ISO.PKCS.ContentInfo PasswordEncryptData(
            Factory factory, SecurityStore scope, IRand rand, bool useCipherPBE, 
            ISecretKey password, CMSData data, ASN1.ISO.Attributes attributes)
	    {
		    // получить параметры алгоритма шифрования
		    ASN1.ISO.AlgorithmIdentifier passwordAlgorithm = CipherAlgorithm(rand); 

            // при наличии параметров шифрования по паролю
		    if (useCipherPBE && passwordAlgorithm != null)
		    {
			    // закодировать структуру CMS
			    ASN1.ISO.PKCS.PKCS7.EncryptedData encryptedData = CMS.EncryptData(
					factory, scope, password, passwordAlgorithm, data, attributes
				); 
			    // вернуть закодированную структуру
			    return new ASN1.ISO.PKCS.ContentInfo(
			        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS7.OID.encryptedData), encryptedData
			    ); 
		    }
		    else {
		        // получить параметры алгоритма наследования ключа
		        ASN1.ISO.AlgorithmIdentifier[] keyDeriveAlgorithms = 
                    new ASN1.ISO.AlgorithmIdentifier[] { KDFAlgorithm(rand) };

				// получить параметры алгоритма шифрования
				ASN1.ISO.AlgorithmIdentifier cipherAlgorithm = BaseCulture.CipherAlgorithm(rand);

				// проверить указание параметров
				if (cipherAlgorithm == null) throw new NotSupportedException();

				// получить алгоритм шифрования ключа
				ASN1.ISO.AlgorithmIdentifier keyWrapAlgorithm = BaseCulture.KeyWrapAlgorithm(rand);

				// скорректировать алгоритм шифрования ключа
				// if (cms) keyWrapAlgorithm = new ASN1.ISO.AlgorithmIdentifier(
				//	new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS9.OID.smime_pwri_kek),
				//	cipherAlgorithm
				//);
				// проверить указание параметров
				if (keyWrapAlgorithm == null) throw new NotSupportedException();

				// получить параметры алгоритма шифрования ключа
				ASN1.ISO.AlgorithmIdentifier[] keyWrapAlgorithms = 
                    new ASN1.ISO.AlgorithmIdentifier[] { keyWrapAlgorithm };

		        // зашифровать данные
		        ASN1.ISO.PKCS.PKCS7.EnvelopedData envelopedData = CMS.PasswordEncryptData(
			        factory, scope, rand, new ISecretKey[] { password }, cipherAlgorithm, 
			        keyDeriveAlgorithms, keyWrapAlgorithms, data, attributes
		        ); 
		        // вернуть закодированную структуру
		        return new ASN1.ISO.PKCS.ContentInfo(
			        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS7.OID.envelopedData), envelopedData
		        ); 
		    }
	    }
 	}
}
