using System;
using System.Collections.Generic;

namespace Aladdin.CAPI
{
	///////////////////////////////////////////////////////////////////////////
	// Базовый класс для фабрики алгоритмов
	///////////////////////////////////////////////////////////////////////////
	public abstract class Factory : RefObject
	{
        // получить идентификатор ключа
        public virtual string ConvertKeyName(string name) { return name; } 
    
	    // поддерживаемые фабрики кодирования ключей
	    public virtual Dictionary<String, KeyFactory> KeyFactories() 
        { 
	        // поддерживаемые фабрики кодирования ключей
            return new Dictionary<String, KeyFactory>(); 
        }
	    // получить фабрику кодирования ключей
	    public KeyFactory GetKeyFactory(string keyOID)
        {
            // указать идентификатор ключа
            keyOID = ConvertKeyName(keyOID); 

            // получить фабрики кодирования ключей
            Dictionary<String, KeyFactory> keyFactories = KeyFactories(); 

	        // получить фабрику кодирования ключей
            return keyFactories.ContainsKey(keyOID) ? keyFactories[keyOID] : null; 
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
        // создать алгоритм генерации ключей
		public virtual KeyPairGenerator CreateGenerator(
            SecurityObject scope, IRand rand, string keyOID, IParameters parameters) 
        { 
            // получить идентификатор ключа
            keyOID = ConvertKeyName(keyOID); 

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
        // получить идентификатор алгоритма
        public virtual string ConvertAlgorithmName(string name) { return name; } 
    
		// создать алгоритм для параметров
        public T CreateAlgorithm<T>(SecurityStore scope,
            ASN1.ISO.AlgorithmIdentifier parameters) where T : IAlgorithm
        {
            // создать алгоритм
            return CreateAlgorithm<T>(scope, parameters.Algorithm.Value, parameters.Parameters); 
        }
        public T CreateAlgorithm<T>(SecurityStore scope,
            string oid, ASN1.IEncodable parameters) where T : IAlgorithm
        {
            // создать алгоритм
            return (T)CreateAlgorithm(scope, oid, parameters, typeof(T)); 
        }
		// создать алгоритм для параметров
        public virtual IAlgorithm CreateAlgorithm(SecurityStore scope,
            string oid, ASN1.IEncodable parameters, Type type)
        {
            // получить идентификатор алгоритма
            oid = ConvertAlgorithmName(oid); 

            // создать алгоритм
            return CreateAggregatedAlgorithm(this, scope, oid, parameters, type); 
        }
        protected internal virtual IAlgorithm CreateAggregatedAlgorithm(
            Factory outer, SecurityStore scope,
            string oid, ASN1.IEncodable parameters, Type type)
        {
            // создать агрегированную фабрику
            using (Factory factory = AggregatedFactory.Create(outer, this))
            {        
                // создать алгоритм
                return CreateAlgorithm(factory, scope, oid, parameters, type); 
            }
        }
		// создать алгоритм для параметров
        protected internal virtual IAlgorithm CreateAlgorithm(
            Factory factory, SecurityStore scope,
            string oid, ASN1.IEncodable parameters, Type type)
		{ 
            // вызвать базовую функцию
            return Factory.RedirectAlgorithm(factory, scope, oid, parameters, type); 
		}
        ///////////////////////////////////////////////////////////////////////
		// Создать режим блочного шифрования 
        ///////////////////////////////////////////////////////////////////////
        public static Cipher Create(Factory factory, SecurityStore scope, 
            string name, ASN1.IEncodable parameters, byte[] iv)
        {
            // разделить имя на части
            string[] parts = name.Split('/'); name = parts[0]; 

            // указать режим шифрования и дополнения
            string mode = (parts.Length > 1) ? parts[1].ToUpper() : String.Empty; 

            // создать блочный режим шифрования
            using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(
                scope, name, parameters))
            {
                // проверить наличие алгоритма
                if (blockCipher == null) return null; 

                // определить размер блока
                int blockSize = blockCipher.BlockSize; CipherMode cipherMode = null;

                // указать режим ECB
                if (mode.Length == 0 || mode == "NONE" || mode == "ECB") cipherMode = new CipherMode.ECB(); 

                // для режима CBC
                else if (mode.StartsWith("CBC")) { mode = mode.Substring(3); 
                
                    // проверить наличие синхропосылки
                    if (iv == null) throw new ArgumentException(); 
              
                    // прочитать размер блока для режима
                    if (mode.Length != 0) { int modeBits = Int32.Parse(mode); 

                        // проверить корректность размера блока
                        if (modeBits == 0 || (modeBits % 8) != 0) throw new ArgumentException(); 

                        // указать размер блока
                        blockSize = modeBits % 8; 
                    }
                    // указать используемый ражим
                    cipherMode = new CipherMode.CBC(iv, blockSize); 
                }
                // для режима CFB
                else if (mode.StartsWith("CFB")) { mode = mode.Substring(3); 
                
                    // проверить наличие синхропосылки
                    if (iv == null) throw new ArgumentException(); 

                    // прочитать размер блока для режима
                    if (mode.Length != 0) { int modeBits = Int32.Parse(mode); 

                        // проверить корректность размера блока
                        if (modeBits == 0 || (modeBits % 8) != 0) throw new ArgumentException(); 

                        // указать размер блока
                        blockSize = modeBits % 8; 
                    }
                    // указать используемый ражим
                    cipherMode = new CipherMode.CFB(iv, blockSize); 
                }
                // для режима OFB
                else if (mode.StartsWith("OFB")) { mode = mode.Substring(3); 
                
                    // проверить наличие синхропосылки
                    if (iv == null) throw new ArgumentException(); 

                    // прочитать размер блока для режима
                    if (mode.Length != 0) { int modeBits = Int32.Parse(mode); 

                        // проверить корректность размера блока
                        if (modeBits == 0 || (modeBits % 8) != 0) throw new ArgumentException(); 

                        // указать размер блока
                        blockSize = modeBits % 8; 
                    }
                    // указать используемый ражим
                    cipherMode = new CipherMode.OFB(iv, blockSize); 
                }
                // для режима OFB
                else if (mode.StartsWith("OFB")) { mode = mode.Substring(3); 
                
                    // проверить наличие синхропосылки
                    if (iv == null) throw new ArgumentException(); 

                    // прочитать размер блока для режима
                    if (mode.Length != 0) { int modeBits = Int32.Parse(mode); 

                        // проверить корректность размера блока
                        if (modeBits == 0 || (modeBits % 8) != 0) throw new ArgumentException(); 

                        // указать размер блока
                        blockSize = modeBits % 8; 
                    }
                    // указать используемый ражим
                    cipherMode = new CipherMode.OFB(iv, blockSize); 
                }
                // для режима CTR
                else if (mode.StartsWith("CTR")) { mode = mode.Substring(3); 
                
                    // проверить наличие синхропосылки
                    if (iv == null) throw new ArgumentException(); 

                    // прочитать размер блока для режима
                    if (mode.Length != 0) { int modeBits = Int32.Parse(mode); 

                        // проверить корректность размера блока
                        if (modeBits == 0 || (modeBits % 8) != 0) throw new ArgumentException(); 

                        // указать размер блока
                        blockSize = modeBits % 8; 
                    }
                    // указать используемый ражим
                    cipherMode = new CipherMode.CTR(iv, blockSize); 
                }
                // режим не поддерживается
                else throw new NotSupportedException(); 
                 
                // создать режим блочного шифрования 
                return blockCipher.CreateBlockMode(cipherMode); 
            }
        }
        ///////////////////////////////////////////////////////////////////////
		// Перенаправление алгоритмов 
        ///////////////////////////////////////////////////////////////////////
        public static IAlgorithm RedirectAlgorithm(Factory factory, 
            SecurityStore scope, string oid, ASN1.IEncodable parameters, Type type)
		{ 
			// для алгоритмов вычисления имитовставки
			if (type == typeof(Mac))
			{
				if (oid == ASN1.ISO.PKCS.PKCS5.OID.pbmac1) 
				{
					// раскодировать параметры алгоритма
					ASN1.ISO.PKCS.PKCS5.PBMAC1Parameter pbeParameters = 
						new ASN1.ISO.PKCS.PKCS5.PBMAC1Parameter(parameters); 

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
						new ASN1.ISO.PKCS.PKCS5.PBES2Parameter(parameters); 

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
						new ASN1.ISO.PKCS.PKCS5.PBKDF2Parameter(parameters);

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
    		    using (Cipher cipher = factory.CreateAlgorithm<Cipher>(scope, oid, parameters))
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
			    return factory.CreateAlgorithm<Encipherment>(scope, oid, parameters); 
            }
		    // для алгоритмов передачи ключа
		    else if (type == typeof(TransportKeyUnwrap))
		    {
    		    // получить алгоритм расшифрования данных
			    return factory.CreateAlgorithm<Decipherment>(scope, oid, parameters); 
            }
			return null; 
		}
	}
}
