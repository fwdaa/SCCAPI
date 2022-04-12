using System;
using System.IO;
using System.Collections.Generic;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.GOST.PKCS11
{
    ///////////////////////////////////////////////////////////////////////////////
    // Криптографический провайдер
    ///////////////////////////////////////////////////////////////////////////////
    public class Provider : CAPI.PKCS11.Provider
    {
        // возможность импорта ключевой пары в память
        private Module module; private bool canImport; 
    
        // фабрики кодирования ключей 
        private Dictionary<String, KeyFactory> keyFactories; 
    
	    // конструктор
        public Provider(string name, bool canImport) : this(null, name, canImport) {}

	    // конструктор
	    public Provider(Module module, string name, bool canImport) : base(name)
        { 
            // сохранить переданне параметры
            this.module = module; this.canImport = canImport; 

            // создать список фабрик кодирования ключей
            keyFactories = new Dictionary<String, KeyFactory>(); 

            // заполнить список фабрик кодирования ключей
            keyFactories.Add(ASN1.GOST.OID.gostR3410_2001, 
                new GOST.GOSTR3410.ECKeyFactory(ASN1.GOST.OID.gostR3410_2001)
            ); 
            keyFactories.Add(ASN1.GOST.OID.gostR3410_2012_256, 
                new GOST.GOSTR3410.ECKeyFactory(ASN1.GOST.OID.gostR3410_2012_256)
            ); 
            keyFactories.Add(ASN1.GOST.OID.gostR3410_2012_512, 
                new GOST.GOSTR3410.ECKeyFactory(ASN1.GOST.OID.gostR3410_2012_512)
            ); 
        }
        // интерфейс вызова функций
        public override Module Module { get { return module; }}

        // возможность генерации и импорта ключевой пары в памяти
        public override bool CanImportSessionPair(CAPI.PKCS11.Applet applet) { return canImport; } 
    
	    // поддерживаемые фабрики кодирования ключей
	    public override Dictionary<String, KeyFactory> KeyFactories() { return keyFactories; } 

	    public override string[] GeneratedKeys(SecurityStore scope) 
	    {
            // проверить тип области видимости
            if (!(scope is CAPI.PKCS11.Applet)) return new string[0]; 

            // выполнить преобразование типа
            CAPI.PKCS11.Applet applet = (CAPI.PKCS11.Applet)scope;

            // создать список ключей
            List<String> keyOIDs = new List<String>(); 
        
            // проверить поддержку ключа
            if (applet.Supported(API.CKM_GOSTR3410_KEY_PAIR_GEN, 0, 0)) 
            {
                // добавить ключи в список
                keyOIDs.Add(ASN1.GOST.OID.gostR3410_2001); 
                keyOIDs.Add(ASN1.GOST.OID.gostR3410_2012_256); 
            }
            // проверить поддержку ключа
            if (applet.Supported(API.CKM_GOSTR3410_512_KEY_PAIR_GEN, 0, 0)) 
            {
                // добавить ключ в список
                keyOIDs.Add(ASN1.GOST.OID.gostR3410_2012_512); 
            }
            // вернуть список ключей
            return keyOIDs.ToArray(); 
	    }
		// атрибуты открытого и личного ключа
		public override CAPI.PKCS11.Attribute[] PublicKeyAttributes(
            CAPI.PKCS11.Applet applet, IPublicKey publicKey, MechanismInfo info)
        {
	        // проверить тип ключа
	        if (publicKey is GOST.GOSTR3410.IECPublicKey)
	        {
		        // выполнить преобразование типа
		        GOST.GOSTR3410.IECPublicKey ecPublicKey = (GOST.GOSTR3410.IECPublicKey)publicKey; 

		        // получить атрибуты ключа
		        return GOSTR3410.PublicKey.GetAttributes(this, ecPublicKey); 
	        }
            return null; 
        }
		public override CAPI.PKCS11.Attribute[] PrivateKeyAttributes(
            CAPI.PKCS11.Applet applet, IPrivateKey privateKey, MechanismInfo info)
        {
	        // проверить тип ключа
	        if (privateKey is GOST.GOSTR3410.IECPrivateKey)
	        {
		        // выполнить преобразование типа
		        GOST.GOSTR3410.IECPrivateKey ecPrivateKey = (GOST.GOSTR3410.IECPrivateKey)privateKey; 

		        // получить атрибуты ключа
		        return GOST.PKCS11.GOSTR3410.PrivateKey.GetAttributes(this, ecPrivateKey); 
	        }
            return null; 
        }
	    public override CAPI.PKCS11.Attribute[] SecretKeyAttributes(
            SecretKeyFactory keyFactory, int keySize, bool hasValue) 
        { 
            if (Object.ReferenceEquals(keyFactory, Keys.GOST.Instance))
            {
                // закодировать идентификатор таблицы подстановок
                byte[] encodedOID = new ASN1.ObjectIdentifier(ASN1.GOST.OID.encrypts_A).Encoded; 
            
                // выделить память для атрибутов
                return new CAPI.PKCS11.Attribute[] { 

                    // указать требуемые атрибуты
                    CreateAttribute(API.CKA_KEY_TYPE, API.CKK_GOST28147), 

                    // указать требуемые атрибуты
                    CreateAttribute(API.CKA_GOST28147_PARAMS, encodedOID)
                }; 
            }
            // вызвать базовую функцию
            return base.SecretKeyAttributes(keyFactory, keySize, hasValue); 
        }
		public override IPublicKey ConvertPublicKey(
            CAPI.PKCS11.Applet scope, CAPI.PKCS11.SessionObject obj)
        {
            // определить тип ключа
            ulong keyType = obj.GetKeyType(); 

	        // для 512-битного ключа
	        if (keyType == API.CKK_GOSTR3410_512)
	        {
                // указать идентификатор ключа
                string keyOID = ASN1.GOST.OID.gostR3410_2012_512; 

		        // преобразовать тип ключа
		        return new GOST.PKCS11.GOSTR3410.PublicKey(this, obj, keyOID); 
	        }
	        // для 256-битного ключа
	        if (keyType == API.CKK_GOSTR3410) 
	        {
		        // получить атрибуты ключа
		        CAPI.PKCS11.Attributes keyAttributes = GetKeyAttributes(obj, 
                    new CAPI.PKCS11.Attribute(API.CKA_GOSTR3411_PARAMS, 
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.hashes_cryptopro).Encoded) 
                ); 
                // определить параметры ключа
                ASN1.ObjectIdentifier hashOID  = new ASN1.ObjectIdentifier(
                    ASN1.Encodable.Decode((byte[])keyAttributes[API.CKA_GOSTR3411_PARAMS].Value)
                ); 
                // в зависимости от идентификатора алгоитма хэширования
                if (hashOID.Value == ASN1.GOST.OID.gostR3411_2012_256)
                {
                    // указать идентификатор ключа
                    string keyOID = ASN1.GOST.OID.gostR3410_2012_256; 

                    // преобразовать тип ключа
                    return new GOST.PKCS11.GOSTR3410.PublicKey(this, obj, keyOID); 
                }
                else { 
                    // указать идентификатор ключа
                    string keyOID = ASN1.GOST.OID.gostR3410_2001;

                    // преобразовать тип ключа
                    return new GOST.PKCS11.GOSTR3410.PublicKey(this, obj, keyOID); 
                }
	        }
            return null; 
        }
		// преобразование ключей
		public override CAPI.PKCS11.PrivateKey ConvertPrivateKey(
            SecurityObject scope, CAPI.PKCS11.SessionObject obj, IPublicKey publicKey)
        {
            // определить тип ключа
            ulong keyType = obj.GetKeyType(); 

	        // для 256-битного ключа
	        if (keyType == API.CKK_GOSTR3410) 
	        {
		        // преобразовать тип ключа
		        return new GOST.PKCS11.GOSTR3410.PrivateKey(this, scope, obj, publicKey); 
	        }
	        // для 512-битного ключа
	        if (keyType == API.CKK_GOSTR3410_512)
	        {
		        // преобразовать тип ключа
		        return new GOST.PKCS11.GOSTR3410.PrivateKey(this, scope, obj, publicKey); 
	        }
            return null; 
        }
		// создать алгоритм генерации ключей
		protected override CAPI.KeyPairGenerator CreateGenerator(
			CAPI.Factory factory, SecurityObject scope, 
            IRand rand, string keyOID, IParameters parameters)
        {
	        // проверить тип параметров
            if (keyOID == ASN1.GOST.OID.gostR3410_2001     || 
                keyOID == ASN1.GOST.OID.gostR3410_2012_256)
	        {
		        // выполнить преобразование типа
		        GOST.GOSTR3410.INamedParameters gostParameters = 
			        (GOST.GOSTR3410.INamedParameters)parameters; 

		        // указать идентификатор алгоритма
		        ulong algID = API.CKM_GOSTR3410_KEY_PAIR_GEN; 

		        // найти подходящую смарт-карту
		        using (CAPI.PKCS11.Applet applet = FindApplet(scope, algID, 0, 0)) 
                {
		            // проверить наличие смарт-карты
		            if (applet == null) return null; 

	                // создать алгоритм генерации ключей
	                return new GOST.PKCS11.GOSTR3410.KeyPairGenerator(
                        applet, scope, rand, gostParameters
                    );
                }
            }
	        // проверить тип параметров
            if (keyOID == ASN1.GOST.OID.gostR3410_2012_512)
	        {
		        // выполнить преобразование типа
		        GOST.GOSTR3410.INamedParameters gostParameters = 
			        (GOST.GOSTR3410.INamedParameters)parameters; 

		        // указать идентификатор алгоритма
		        ulong algID = API.CKM_GOSTR3410_512_KEY_PAIR_GEN; 

		        // найти подходящую смарт-карту
		        using (CAPI.PKCS11.Applet applet = FindApplet(scope, algID, 0, 0)) 
                {
		            // проверить наличие смарт-карты
		            if (applet == null) return null; 

	                // создать алгоритм генерации ключей
	                return new GOST.PKCS11.GOSTR3410.KeyPairGenerator(
                        applet, scope, rand, gostParameters
                    );
                }
            }
	        return null; 
        }
		// создать алгоритм для параметров
		protected override IAlgorithm CreateAlgorithm(
			CAPI.Factory factory, SecurityStore scope, string oid, ASN1.IEncodable parameters, Type type)
        {
	        for (int i = 0; i < 1; i++)
            { 
	            // для алгоритмов хэширования
	            if (type == typeof(CAPI.Hash))
	            {
		            if (oid == ASN1.GOST.OID.gostR3411_94) 
		            {
                        // указать идентификатор таблицы подстановок по умолчанию
                        ASN1.ObjectIdentifier sboxOID = new ASN1.ObjectIdentifier(ASN1.GOST.OID.hashes_cryptopro); 
                    
                        // проверить наличие параметров
                        if (!ASN1.Encodable.IsNullOrEmpty(parameters)) 
                        {
                            // раскодировать идентификатор параметров
                            sboxOID = new ASN1.ObjectIdentifier(parameters);
                        }
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_GOSTR3411, sboxOID.Encoded); 
                    
                        // создать алгоритм хэширования
                        CAPI.Hash hashAlgorithm = Creator.CreateHash(this, scope, mechanism); 
                    
                        // проверить поддержку алгоритма
                        if (hashAlgorithm == null) break; return hashAlgorithm; 
		            }
		            else if (oid == ASN1.GOST.OID.gostR3411_2012_256) 
		            {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_GOSTR3411_2012_256); 
                    
                        // создать алгоритм хэширования
                        CAPI.Hash hashAlgorithm = Creator.CreateHash(this, scope, mechanism); 
                    
                        // проверить поддержку алгоритма
                        if (hashAlgorithm == null) break; return hashAlgorithm; 
		            }
		            else if (oid == ASN1.GOST.OID.gostR3411_2012_512) 
		            {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_GOSTR3411_2012_512); 
                    
                        // создать алгоритм хэширования
                        CAPI.Hash hashAlgorithm = Creator.CreateHash(this, scope, mechanism); 
                    
                        // проверить поддержку алгоритма
                        if (hashAlgorithm == null) break; return hashAlgorithm; 
		            }
	            }
	            // для алгоритмов вычисления имитовставки
	            else if (type == typeof(CAPI.Mac))
	            {
		            if (oid == ASN1.GOST.OID.gostR3411_94_HMAC) 
		            {
                        // указать идентификатор таблицы подстановок по умолчанию
                        ASN1.ObjectIdentifier sboxOID = new ASN1.ObjectIdentifier(ASN1.GOST.OID.hashes_cryptopro); 
                    
                        // проверить наличие параметров
                        if (!ASN1.Encodable.IsNullOrEmpty(parameters)) 
                        {
                            // раскодировать идентификатор параметров
                            sboxOID = new ASN1.ObjectIdentifier(parameters);
                        }
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_GOSTR3411_HMAC, sboxOID.Encoded); 
                    
                        // создать алгоритм вычисления имитовставки
                        CAPI.Mac macAlgorithm = Creator.CreateMac(this, scope, mechanism, null);
                        
                        // проверить поддержку алгоритма
                        if (macAlgorithm == null) break; return macAlgorithm; 
		            }
		            else if (oid == ASN1.GOST.OID.gostR3411_2012_HMAC_256) 
		            {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_GOSTR3411_2012_256_HMAC); 
                    
                        // создать алгоритм вычисления имитовставки
                        CAPI.Mac macAlgorithm = Creator.CreateMac(this, scope, mechanism, null);
                        
                        // проверить поддержку алгоритма
                        if (macAlgorithm == null) break; return macAlgorithm; 
		            }
		            else if (oid == ASN1.GOST.OID.gostR3411_2012_HMAC_512) 
		            {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_GOSTR3411_2012_512_HMAC); 
                    
                        // создать алгоритм вычисления имитовставки
                        CAPI.Mac macAlgorithm = Creator.CreateMac(this, scope, mechanism, null);
                        
                        // проверить поддержку алгоритма
                        if (macAlgorithm == null) break; return macAlgorithm; 
		            }
		            else if (oid == ASN1.GOST.OID.gost28147_89_MAC) 
		            {
			            // раскодировать параметры алгоритма
			            ASN1.GOST.GOST28147CipherParameters algParameters = 
				            new ASN1.GOST.GOST28147CipherParameters(parameters); 

			            // определить идентификатор таблицы подстановок
			            ASN1.ObjectIdentifier sboxOID = algParameters.ParamSet; 

                        // указать атрибуты ключа
                        CAPI.PKCS11.Attributes attributes = new CAPI.PKCS11.Attributes(
                            CreateAttribute(API.CKA_GOST28147_PARAMS, sboxOID.Encoded)
                        ); 
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(
                            API.CKM_GOST28147_MAC, algParameters.IV.Value
                        ); 
                        // создать алгоритм вычисления имитовставки
                        CAPI.Mac macAlgorithm = Creator.CreateMac(this, scope, mechanism, attributes);
                        
                        // проверить поддержку алгоритма
                        if (macAlgorithm == null) break; return macAlgorithm; 
                    }
	            }
	            // для алгоритмов симметричного шифрования
	            else if (type == typeof(CAPI.Cipher))
	            {
		            if (oid == ASN1.GOST.OID.gost28147_89)
		            { 
			            // раскодировать параметры алгоритма
			            ASN1.GOST.GOST28147CipherParameters algParameters = 
				            new ASN1.GOST.GOST28147CipherParameters(parameters); 

			            // определить идентификатор таблицы подстановок
			            ASN1.ObjectIdentifier paramsOID = algParameters.ParamSet; 

                        // указать атрибуты ключа
                        CAPI.PKCS11.Attributes attributes = new CAPI.PKCS11.Attributes(
                            CreateAttribute(API.CKA_GOST28147_PARAMS, paramsOID.Encoded)
                        ); 
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_GOST28147, algParameters.IV.Value); 

                        // создать алгоритм вычисления шифрования
                        CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, attributes);

                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
		            }
	            }
                // для алгоритмов симметричного шифрования
                else if (type == typeof(IBlockCipher))
                {
                    if (oid == "GOST28147")
                    { 
                        // раскодировать параметры алгоритма
                        ASN1.ObjectIdentifier cipherParameters = new ASN1.ObjectIdentifier(parameters); 
                    
                        // создать блочный алгоритм шифрования
                        return Creator.CreateGOST28147(this, scope, cipherParameters.Value); 
                    }
                }
	            // для алгоритмов наследования ключа
	            else if (type == typeof(CAPI.KeyDerive))
                {
			        if (oid == ASN1.ISO.PKCS.PKCS5.OID.pbkdf2) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBKDF2Parameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBKDF2Parameter(parameters);
                
                        // инициализировать переменные
                        ulong prf = 0; byte[] prfData = null; int keySize = -1; 

		                // при указании размера ключа
		                if (pbeParameters.KeyLength != null)
                        {
		                    // прочитать размер ключа
		                    keySize = pbeParameters.KeyLength.Value.IntValue;
		                }
                        // определить идентификатор алгоритма вычисления имитовставки
                        string hmacOID = pbeParameters.PRF.Algorithm.Value; 

                        // в зависимости от идентификатора
                        if (hmacOID == ASN1.GOST.OID.gostR3411_94_HMAC) 
                        {
                            // преобразовать идентификатор алгоритма вычисления имитовставки
                            prf = API.CKP_PKCS5_PBKD2_HMAC_GOSTR3411;
                    
                            // извлечь параметры хэширования
                            ASN1.IEncodable hashParameters = pbeParameters.PRF.Parameters; 
                    
                            // проверить наличие идентификатора
                            if (ASN1.Encodable.IsNullOrEmpty(hashParameters)) prfData = null; 
                            else {
                                // закодировать значение идентификатора
                                prfData = parameters.Encoded;
                            }
                        } 
                        else if (hmacOID == ASN1.GOST.OID.gostR3411_2012_HMAC_256)
                        {
                            // преобразовать идентификатор алгоритма вычисления имитовставки
                            prf = API.CKP_PKCS5_PBKD2_HMAC_GOSTR3411_2012_256; prfData = null; 
                        }
                        else if (hmacOID == ASN1.GOST.OID.gostR3411_2012_HMAC_512)
                        {
                            // преобразовать идентификатор алгоритма вычисления имитовставки
                            prf = API.CKP_PKCS5_PBKD2_HMAC_GOSTR3411_2012_256; prfData = null; 
                        }
                        // извлечь salt-значение
                        else break; ASN1.OctetString salt = new ASN1.OctetString(pbeParameters.Salt);

                        // создать алгоритм наследования ключа
                        KeyDerive keyDerive = Creator.CreateDerivePBKDF2(
                            this, scope, prf, prfData, salt.Value, 
                            pbeParameters.IterationCount.Value.IntValue, keySize
                        ); 
                        // проверить поддержку алгоритма
                        if (keyDerive == null) break; return keyDerive; 
			        }
		            else if (oid == ASN1.GOST.OID.keyMeshing_cryptopro) 
		            {
			            // раскодировать параметры алгоритма
			            ASN1.ObjectIdentifier sboxOID = new ASN1.ObjectIdentifier(parameters); 

                        // создать алгоритм наследования ключа
                        KeyDerive keyDerive = Creator.CreateKeyMeshing(this, scope, sboxOID.Value); 

                        // проверить поддержку алгоритма
                        if (keyDerive == null) break; return keyDerive; 
                    }
                }
	            // для алгоритмов шифрования ключа
	            else if (type == typeof(CAPI.KeyWrap))
	            {
		            if (oid == ASN1.GOST.OID.keyWrap_none) 
		            {
			            // раскодировать параметры алгоритма
			            ASN1.GOST.KeyWrapParameters wrapParameters = 
				            new ASN1.GOST.KeyWrapParameters(parameters); 

                        // проверить наличие UKM
                        if (wrapParameters.Ukm == null) throw new InvalidDataException(); 

			            // определить идентификатор таблицы подстановок
			            string sboxOID = wrapParameters.ParamSet.Value; 

                        // создать алгоритм шифрования ключа
                        KeyWrap keyWrap = Creator.CreateWrapRFC4357(
                            this, scope, API.CKD_NULL, sboxOID, wrapParameters.Ukm.Value
                        ); 
                        // проверить поддержку алгоритма
                        if (keyWrap == null) break; return keyWrap; 
		            }
			        else if (oid == ASN1.GOST.OID.keyWrap_cryptopro) 
			        {
			            // раскодировать параметры алгоритма
			            ASN1.GOST.KeyWrapParameters wrapParameters = 
				            new ASN1.GOST.KeyWrapParameters(parameters); 
                
                        // проверить наличие UKM
                        if (wrapParameters.Ukm == null) throw new InvalidDataException(); 

                        // извлечь идентификатор набора параметров
                        String sboxOID = wrapParameters.ParamSet.Value; 
                
                        // создать алгоритм шифрования ключа
                        KeyWrap keyWrap = Creator.CreateWrapRFC4357(
                            this, scope, API.CKD_CPDIVERSIFY_KDF, sboxOID, wrapParameters.Ukm.Value
                        ); 
                        // проверить поддержку алгоритма
                        if (keyWrap == null) break; return keyWrap; 
                    }
	            }
	            // для алгоритмов подписи хэш-значения
	            else if (type == typeof(CAPI.SignHash))
	            {
		            if (oid == ASN1.GOST.OID.gostR3410_2001) 
		            {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_GOSTR3410); 

                        // создать алгоритм 
                        CAPI.SignHash signHash = Creator.CreateSignHash(this, scope, mechanism);   
                    
                        // проверить поддержку алгоритма
                        if (signHash == null) break; return signHash; 
		            }
		            else if (oid == ASN1.GOST.OID.gostR3410_2012_256) 
		            {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_GOSTR3410_256); 

                        // создать алгоритм 
                        CAPI.SignHash signHash = Creator.CreateSignHash(this, scope, mechanism);   
                    
                        // проверить поддержку алгоритма
                        if (signHash == null) break; return signHash; 
		            }
		            else if (oid == ASN1.GOST.OID.gostR3410_2012_512) 
		            {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_GOSTR3410_512); 

                        // создать алгоритм 
                        CAPI.SignHash signHash = Creator.CreateSignHash(this, scope, mechanism);   
                    
                        // проверить поддержку алгоритма
                        if (signHash == null) break; return signHash; 
		            }
	            }
	            // для алгоритмов подписи хэш-значения
	            else if (type == typeof(CAPI.VerifyHash))
	            {
		            if (oid == ASN1.GOST.OID.gostR3410_2001) 
		            {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_GOSTR3410); 

                        // создать алгоритм 
                        CAPI.VerifyHash verifyHash = Creator.CreateVerifyHash(this, scope, mechanism);   
                    
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; return verifyHash; 
		            }
		            else if (oid == ASN1.GOST.OID.gostR3410_2012_256) 
		            {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_GOSTR3410_256); 

                        // создать алгоритм 
                        CAPI.VerifyHash verifyHash = Creator.CreateVerifyHash(this, scope, mechanism);   
                    
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; return verifyHash; 
		            }
		            else if (oid == ASN1.GOST.OID.gostR3410_2012_512) 
		            {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_GOSTR3410_512); 

                        // создать алгоритм 
                        CAPI.VerifyHash verifyHash = Creator.CreateVerifyHash(this, scope, mechanism);   
                    
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; return verifyHash; 
		            }
	            }
	            // для алгоритмов подписи данных
	            else if (type == typeof(CAPI.SignData))
	            {
		            if (oid == ASN1.GOST.OID.gostR3411_94_R3410_2001) 
		            {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_GOSTR3410_WITH_GOSTR3411); 
                    
                        // создать алгоритм подписи данных
                        CAPI.SignData signData = Creator.CreateSignData(this, scope, mechanism);
                        
                        // проверить поддержку алгоритма
                        if (signData == null) break; return signData; 
		            }
		            if (oid == ASN1.GOST.OID.gostR3411_2012_R3410_2012_256) 
		            {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_GOSTR3410_WITH_GOSTR3411_2012_256); 
                    
                        // создать алгоритм подписи данных
                        CAPI.SignData signData = Creator.CreateSignData(this, scope, mechanism);
                        
                        // проверить поддержку алгоритма
                        if (signData == null) break; return signData; 
		            }
		            if (oid == ASN1.GOST.OID.gostR3411_2012_R3410_2012_512) 
		            {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_GOSTR3410_WITH_GOSTR3411_2012_512); 
                    
                        // создать алгоритм подписи данных
                        CAPI.SignData signData = Creator.CreateSignData(this, scope, mechanism);
                        
                        // проверить поддержку алгоритма
                        if (signData == null) break; return signData; 
		            }
	            }
	            // для алгоритмов подписи данных
	            else if (type == typeof(CAPI.VerifyData))
	            {
		            if (oid == ASN1.GOST.OID.gostR3411_94_R3410_2001) 
		            {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_GOSTR3410_WITH_GOSTR3411); 
                    
                        // создать алгоритм подписи данных
                        CAPI.VerifyData verifyData = Creator.CreateVerifyData(this, scope, mechanism);
                        
                        // проверить поддержку алгоритма
                        if (verifyData == null) break; return verifyData; 
		            }
		            if (oid == ASN1.GOST.OID.gostR3411_2012_R3410_2012_256) 
		            {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_GOSTR3410_WITH_GOSTR3411_2012_256); 
                    
                        // создать алгоритм подписи данных
                        CAPI.VerifyData verifyData = Creator.CreateVerifyData(this, scope, mechanism);
                        
                        // проверить поддержку алгоритма
                        if (verifyData == null) break; return verifyData; 
		            }
		            if (oid == ASN1.GOST.OID.gostR3411_2012_R3410_2012_512) 
		            {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_GOSTR3410_WITH_GOSTR3411_2012_512); 
                    
                        // создать алгоритм подписи данных
                        CAPI.VerifyData verifyData = Creator.CreateVerifyData(this, scope, mechanism);
                        
                        // проверить поддержку алгоритма
                        if (verifyData == null) break; return verifyData; 
		            }
	            }
	            // для алгоритмов согласования общего ключа
	            else if (type == typeof(IKeyAgreement))
	            {
		            if (oid == ASN1.GOST.OID.gostR3410_2001)
		            {
                        // указать идентификатор алгоритма
                        ulong algID = API.CKM_GOSTR3410_DERIVE; ulong kdf = API.CKD_NULL; 
                    
                        // создать алгоритм согласования ключа
                        KeyAgreement keyAgreement = Creator.CreateKeyAgreement(this, scope, algID, kdf); 
                    
                        // проверить поддержку алгоритма
                        if (keyAgreement == null) break; return keyAgreement; 
		            }
		            if (oid == ASN1.GOST.OID.gostR3410_2012_256)
		            {
                        // указать идентификатор алгоритма
                        ulong algID = API.CKM_GOSTR3410_2012_DERIVE; ulong kdf = API.CKD_NULL; 
                    
                        // создать алгоритм согласования ключа
                        KeyAgreement keyAgreement = Creator.CreateKeyAgreement(this, scope, algID, kdf); 
                    
                        // проверить поддержку алгоритма
                        if (keyAgreement == null) break; return keyAgreement; 
		            }
		            if (oid == ASN1.GOST.OID.gostR3410_2012_512)
		            {
                        // указать идентификатор алгоритма
                        ulong algID = API.CKM_GOSTR3410_2012_DERIVE; ulong kdf = API.CKD_NULL; 
                    
                        // создать алгоритм согласования ключа
                        KeyAgreement keyAgreement = Creator.CreateKeyAgreement(this, scope, algID, kdf); 
                    
                        // проверить поддержку алгоритма
                        if (keyAgreement == null) break; return keyAgreement; 
		            }
	            }
    	        // для алгоритмов согласования общего ключа /* TODO */
/*	            else if (type == typeof(CAPI.TransportKeyWrap))
	            {
		            if (oid == ASN1.GOST.OID.gostR3410_2001) 
		            {
			            // найти подходящую смарт-карту
			            using (CAPI.PKCS11.Applet applet = FindApplet(
                            scope, API.CKM_GOSTR3410_KEY_WRAP, API.CKF_WRAP, 0))
                        {
                            // проверить наличие смарт-карты
                            if (applet == null) break; 

			                // создать алгоритм согласования общего ключа
			                return new Keyx.GOSTR3410.TransportKeyWrap(applet, 8);
                        }
		            }
	            }
*/    	        // для алгоритмов согласования общего ключа
	            else if (type == typeof(CAPI.TransportKeyUnwrap))
	            {
		            if (oid == ASN1.GOST.OID.gostR3410_2001) 
		            {
			            // найти подходящую смарт-карту
			            using (CAPI.PKCS11.Applet applet = FindApplet(
                            scope, API.CKM_GOSTR3410_KEY_WRAP, API.CKF_UNWRAP, 0))
                        {
                            // проверить наличие смарт-карты
                            if (applet == null) break; 

			                // создать алгоритм согласования общего ключа
			                return new Keyx.GOSTR3410.TransportKeyUnwrap(applet);
                        }
		            }
	            }
            }
            // вызвать базовую функцию
            return GOST.Factory.RedirectAlgorithm(factory, scope, oid, parameters, type); 
        }
    }
}
