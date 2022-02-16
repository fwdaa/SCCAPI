using System;

namespace Aladdin.CAPI
{
	///////////////////////////////////////////////////////////////////////////
	// Базовый класс для фабрики алгоритмов
	///////////////////////////////////////////////////////////////////////////
	public abstract class Factory : RefObject
	{
	    // поддерживаемые фабрики кодирования ключей
	    public virtual KeyFactory[] KeyFactories() { return new KeyFactory[0]; }
        
	    // получить фабрику кодирования ключей
	    public KeyFactory GetKeyFactory(string keyOID)
        {
            // для всех фабрик ключей
            foreach (KeyFactory keyFactory in KeyFactories())
            {
                // проверить наличие ключа
                if (keyOID == keyFactory.KeyOID) return keyFactory; 
            }
            return null; 
        }
		// раскодировать открытый ключ
		public IPublicKey DecodePublicKey(ASN1.ISO.PKIX.SubjectPublicKeyInfo subjectPublicKeyInfo)
		{
			// получить параметры алгоритма
			ASN1.ISO.AlgorithmIdentifier algorithmParameters = subjectPublicKeyInfo.Algorithm; 

            // определить идентификатор ключа
            string keyOID = algorithmParameters.Algorithm.Value; 

			// получить фабрику ключей
			KeyFactory keyFactory = GetKeyFactory(keyOID);
 
			// проверить наличие фабрики ключей
			if (keyFactory == null) throw new NotSupportedException();
 
			// раскодировать открытый ключ
			return keyFactory.DecodePublicKey(subjectPublicKeyInfo); 
		}
        // раскодировать личный ключ
		public IPrivateKey DecodePrivateKey(ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo privateKeyInfo)
		{
			// получить параметры алгоритма
			ASN1.ISO.AlgorithmIdentifier algorithmParameters = privateKeyInfo.PrivateKeyAlgorithm; 

            // извлечь идентификатор ключа
            string keyOID = algorithmParameters.Algorithm.Value; 

			// получить фабрику ключей
			KeyFactory keyFactory = GetKeyFactory(keyOID);
 
			// проверить наличие фабрики ключей
			if (keyFactory == null) throw new NotSupportedException();
 
			// раскодировать личный ключ
			return keyFactory.DecodePrivateKey(this, privateKeyInfo); 
		}
		// Раскодировать пару ключей
		public KeyPair DecodeKeyPair(ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo privateKeyInfo)
		{
			// получить параметры алгоритма
			ASN1.ISO.AlgorithmIdentifier algorithmParameters = privateKeyInfo.PrivateKeyAlgorithm; 

            // извлечь идентификатор ключа
            string keyOID = algorithmParameters.Algorithm.Value; 

			// получить фабрику ключей
			KeyFactory keyFactory = GetKeyFactory(keyOID);
 
			// проверить наличие фабрики ключей
			if (keyFactory == null) throw new NotSupportedException();
 
			// раскодировать личный ключ
			return keyFactory.DecodeKeyPair(this, privateKeyInfo); 
		}
        // используемые алгоритмы по умолчанию
        public abstract Culture GetCulture(SecurityStore scope, string keyOID);  
        // указать алгоритмы по умолчанию
        public abstract PBE.PBECulture GetCulture(PBE.PBEParameters parameters, string keyOID); 

        // создать алгоритм генерации ключей
		public virtual KeyPairGenerator CreateGenerator(
            SecurityObject scope, IRand rand, string keyOID, IParameters parameters) 
        { 
            // создать алгоритм генерации ключей
            return CreateAggregatedGenerator(this, scope, rand, keyOID, parameters); 
        }
		protected internal virtual KeyPairGenerator CreateAggregatedGenerator(
            Factory outer, SecurityObject scope, IRand rand, string keyOID, IParameters parameters) 
        { 
            // создать агрегированную фабрику
            using (Factory factory = AggregatedFactory.Create(outer, this))
            {        
                // создать алгоритм генерации ключей
                return CreateGenerator(factory, scope, rand, keyOID, parameters); 
            }
        }
        // создать алгоритм генерации ключей
		protected internal virtual KeyPairGenerator CreateGenerator(
            Factory factory, SecurityObject scope, IRand rand, 
            string keyOID, IParameters parameters) { return null; }

	    // сгенерировать ключи в контейнере
        public KeyPair GenerateKeyPair(SecurityObject scope, IRand rand, 
            byte[] keyID, string keyOID, IParameters parameters, KeyUsage keyUsage, KeyFlags keyFlags) 
	    {
            // создать генератор ключей
            using (KeyPairGenerator generator = CreateGenerator(scope, rand, keyOID, parameters))
            {
                // проверить наличие генератора
                if (generator == null) throw new NotSupportedException();

                // сгенерировать ключи
                return generator.Generate(keyID, keyOID, keyUsage, keyFlags);
            }
	    }
		// создать алгоритм для параметров
        public T CreateAlgorithm<T>(SecurityStore scope,
            ASN1.ISO.AlgorithmIdentifier parameters) where T : IAlgorithm
        {
            // создать алгоритм
            return (T)CreateAlgorithm(scope, parameters, typeof(T)); 
        }
		// создать алгоритм для параметров
        public virtual IAlgorithm CreateAlgorithm(SecurityStore scope,
            ASN1.ISO.AlgorithmIdentifier parameters, Type type)
        {
            // создать алгоритм
            return CreateAggregatedAlgorithm(this, scope, parameters, type); 
        }
        protected internal virtual IAlgorithm CreateAggregatedAlgorithm(
            Factory outer, SecurityStore scope,
            ASN1.ISO.AlgorithmIdentifier parameters, Type type)
        {
            // создать агрегированную фабрику
            using (Factory factory = AggregatedFactory.Create(outer, this))
            {        
                // создать алгоритм
                return CreateAlgorithm(factory, scope, parameters, type); 
            }
        }
		// создать алгоритм для параметров
        protected internal virtual IAlgorithm CreateAlgorithm(
            Factory factory, SecurityStore scope,
            ASN1.ISO.AlgorithmIdentifier parameters, Type type)
		{ 
            // вызвать базовую функцию
            return Factory.RedirectAlgorithm(factory, scope, parameters, type); 
		}
        ///////////////////////////////////////////////////////////////////////
		// Перенаправление алгоритмов 
        ///////////////////////////////////////////////////////////////////////
        public static IAlgorithm RedirectAlgorithm(Factory factory, 
            SecurityStore scope, ASN1.ISO.AlgorithmIdentifier parameters, Type type)
		{ 
            // указать идентификатор алгоритма
            string oid = parameters.Algorithm.Value; 

			// для алгоритмов вычисления имитовставки
			if (type == typeof(Mac))
			{
				if (oid == ASN1.ISO.PKCS.PKCS5.OID.pbmac1) 
				{
					// раскодировать параметры алгоритма
					ASN1.ISO.PKCS.PKCS5.PBMAC1Parameter pbeParameters = 
						new ASN1.ISO.PKCS.PKCS5.PBMAC1Parameter(parameters.Parameters); 

                    // создать алгоритм вычисления имитовставки
                    using (Mac macAlgorithm = factory.CreateAlgorithm<Mac>(
                        scope, pbeParameters.MessageAuthScheme))
                    {
                        // проверить наличие алгоритма
                        if (macAlgorithm == null) return null; 
                    
                        // создать алгоритм наследования ключа по паролю
                        using (KeyDerive derivationAlgorithm = factory.CreateAlgorithm<KeyDerive>(
                            scope, pbeParameters.KeyDerivationFunc))
                        {
                            // проверить наличие алгоритма
                            if (derivationAlgorithm == null) return null; 
                        
                            // создать алгоритм вычисления имитовставки по паролю
                            return new PBE.PBMAC1(derivationAlgorithm, macAlgorithm); 
                        }
                    }
                }
			}
			// для алгоритмов симметричного шифрования
			else if (type == typeof(Cipher))
			{
				if (oid == ASN1.ISO.PKCS.PKCS5.OID.pbes2) 
				{
					// раскодировать параметры алгоритма
					ASN1.ISO.PKCS.PKCS5.PBES2Parameter pbeParameters = 
						new ASN1.ISO.PKCS.PKCS5.PBES2Parameter(parameters.Parameters); 

    		        // создать алгоритм шифрования по паролю
			        return PBE.PBES2.Сreate(factory, scope, pbeParameters); 
    			}
			}
			// для алгоритмов наследования ключа
			else if (type == typeof(KeyDerive))
			{
				if (oid == ASN1.ISO.PKCS.PKCS5.OID.pbkdf2) 
				{
					// раскодировать параметры алгоритма
					ASN1.ISO.PKCS.PKCS5.PBKDF2Parameter pbeParameters = 
						new ASN1.ISO.PKCS.PKCS5.PBKDF2Parameter(parameters.Parameters);

		            // при указании размера ключа
		            int keySize = -1; if (pbeParameters.KeyLength != null)
                    {
			            // прочитать размер ключа
			            keySize = pbeParameters.KeyLength.Value.IntValue;
		            }
                    // создать алгоритм вычисления имитовставки
		            using (Mac macAlgorithm = factory.CreateAlgorithm<Mac>(
                        scope, pbeParameters.PRF))
                    {
                        // проверить наличие алгоритма
                        if (macAlgorithm == null) return null; 
                    
                        // извлечь salt-значение
                        ASN1.OctetString salt = new ASN1.OctetString(pbeParameters.Salt);  
                
                        // создать алгоритм наследования ключа
                        return new PBE.PBKDF2(macAlgorithm, salt.Value, 
                            pbeParameters.IterationCount.Value.IntValue, keySize
                        );
                    }
				}
			}
			// для алгоритмов шифрования ключа
			else if (type == typeof(KeyWrap))
			{
                // получить алгоритм шифрования данных
    		    using (Cipher cipher = factory.CreateAlgorithm<Cipher>(scope, parameters))
                {
                    // вернуть алгоритм шифрования ключа
                    if (cipher == null) return null; 

                    // вернуть алгоритм шифрования ключа
                    return cipher.CreateKeyWrap(PaddingMode.PKCS5);
                }
    		}
		    // для алгоритмов передачи ключа
		    else if (type == typeof(TransportKeyWrap))
		    {
    		    // получить алгоритм зашифрования данных
			    return factory.CreateAlgorithm<Encipherment>(scope, parameters); 
            }
		    // для алгоритмов передачи ключа
		    else if (type == typeof(TransportKeyUnwrap))
		    {
    		    // получить алгоритм расшифрования данных
			    return factory.CreateAlgorithm<Decipherment>(scope, parameters); 
            }
			return null; 
		}
	}
}
