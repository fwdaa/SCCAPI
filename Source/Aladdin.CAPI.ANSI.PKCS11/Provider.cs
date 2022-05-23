using System;
using System.Collections.Generic;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11
{
    ///////////////////////////////////////////////////////////////////////////
    // Криптографический провайдер
    ///////////////////////////////////////////////////////////////////////////
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
            this.module = RefObject.AddRef(module); this.canImport = canImport; 

            // создать список фабрик кодирования ключей
            keyFactories = new Dictionary<String, KeyFactory>(); 

            // заполнить список фабрик кодирования ключей
            keyFactories.Add(ASN1.ISO.PKCS.PKCS1.OID.rsa, 
                new ANSI.RSA.KeyFactory(ASN1.ISO.PKCS.PKCS1.OID.rsa) 
            ); 
            keyFactories.Add(ASN1.ISO.PKCS.PKCS1.OID.rsa_oaep, 
                new ANSI.RSA.KeyFactory(ASN1.ISO.PKCS.PKCS1.OID.rsa_oaep) 
            ); 
            keyFactories.Add(ASN1.ISO.PKCS.PKCS1.OID.rsa_pss, 
                new ANSI.RSA.KeyFactory(ASN1.ISO.PKCS.PKCS1.OID.rsa_pss) 
            ); 
            keyFactories.Add(ASN1.ANSI.OID.x942_dh_public_key, 
                new ANSI.X942.KeyFactory(ASN1.ANSI.OID.x942_dh_public_key) 
            ); 
            keyFactories.Add(ASN1.ANSI.OID.x957_dsa, 
                new ANSI.X957.KeyFactory(ASN1.ANSI.OID.x957_dsa) 
            ); 
            keyFactories.Add(ASN1.ANSI.OID.x962_ec_public_key, 
                new ANSI.X962.KeyFactory(ASN1.ANSI.OID.x962_ec_public_key)
            ); 
        }
        // деструктор
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(module); base.OnDispose();
        }
        // интерфейс вызова функций
        public override Module Module { get { return module; }}

        // возможность генерации и импорта ключевой пары в памяти
        public override bool CanImportSessionPair(CAPI.PKCS11.Applet applet) { return canImport; } 

        // корректная реализация OAEP механизмов
        public virtual bool UseOAEP(CAPI.PKCS11.Applet applet, 
            Parameters.CK_RSA_PKCS_OAEP_PARAMS parameters) { return true; } 

        // корректная реализация PSS механизмов
        public virtual bool UsePSS (CAPI.PKCS11.Applet applet, 
            Parameters.CK_RSA_PKCS_PSS_PARAMS parameters) { return true; }

        // тип структуры передачи параметров механизма PBKDF2
        protected virtual CAPI.PKCS11.PBE.PBKDF2.ParametersType PBKDF2ParametersType 
        {
            // тип структуры передачи параметров механизма PBKDF2
            get { return CAPI.PKCS11.PBE.PBKDF2.ParametersType.Params2; }
        }
	    // поддерживаемые фабрики кодирования ключей
	    public override Dictionary<String, KeyFactory> KeyFactories() { return keyFactories; } 
    
	    public override string[] GeneratedKeys(SecurityStore scope) 
	    {
            // проверить область видимости
            if (!(scope is CAPI.PKCS11.Applet)) return new string[0]; 

            // выполнить преобразование типа
            CAPI.PKCS11.Applet applet = (CAPI.PKCS11.Applet)scope;

            // создать список ключей
            List<String> keyOIDs = new List<String>(); 
        
            // проверить поддержку ключа
            if (applet.Supported(API.CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0)) 
            {
                // добавить ключ в список
                keyOIDs.Add(ASN1.ISO.PKCS.PKCS1.OID.rsa); 
            }
            // проверить поддержку ключа
            if (applet.Supported(API.CKM_X9_42_DH_KEY_PAIR_GEN, 0, 0)) 
            {
                // добавить ключ в список
                keyOIDs.Add(ASN1.ANSI.OID.x942_dh_public_key); 
            }
            // проверить поддержку ключа
            if (applet.Supported(API.CKM_DSA_KEY_PAIR_GEN, 0, 0)) 
            {
                // добавить ключ в список
                keyOIDs.Add(ASN1.ANSI.OID.x957_dsa); 
            }
            // проверить поддержку ключа
            if (applet.Supported(API.CKM_EC_KEY_PAIR_GEN, 0, 0)) 
            {
                // добавить ключ в список
                keyOIDs.Add(ASN1.ANSI.OID.x962_ec_public_key); 
            }
            // вернуть список ключей
            return keyOIDs.ToArray(); 
	    }
	    // преобразование ключей
	    public override IPublicKey ConvertPublicKey(
            CAPI.PKCS11.Applet applet, CAPI.PKCS11.SessionObject obj)
        {
            // определить тип ключа
            ulong keyType = obj.GetKeyType(); 

            if (keyType == API.CKK_RSA) 
            {
                // преобразовать тип ключа
                return new RSA.PublicKey(this, obj); 
            }
            if (keyType == API.CKK_X9_42_DH) 
            {
                // преобразовать тип ключа
                return new X942.PublicKey(this, obj); 
            }
            if (keyType == API.CKK_DSA) 
            {
                // преобразовать тип ключа
                return new X957.PublicKey(this, obj); 
            }
            if (keyType == API.CKK_EC) 
            {
                // получить информацию алгоритма
                MechanismInfo info = applet.GetAlgorithmInfo(API.CKM_EC_KEY_PAIR_GEN); 
            
                // преобразовать тип ключа
                return new X962.PublicKey(this, obj, info.Flags); 
            }
            return null; 
        }
	    public override CAPI.PKCS11.PrivateKey ConvertPrivateKey(
            SecurityObject scope, CAPI.PKCS11.SessionObject obj, IPublicKey publicKey)
        {
            // определить тип ключа
            ulong keyType = obj.GetKeyType(); 

            if (keyType == API.CKK_RSA) 
            {
                // выполнить преобразование типа
                ANSI.RSA.IPublicKey rsaPublicKey = (ANSI.RSA.IPublicKey) publicKey; 
            
                // преобразовать тип ключа
                return new RSA.PrivateKey(this, scope, obj, rsaPublicKey); 
            }
            if (keyType == API.CKK_X9_42_DH) 
            {
                // выполнить преобразование типа
                ANSI.X942.IPublicKey dhPublicKey = (ANSI.X942.IPublicKey) publicKey; 
            
                // преобразовать тип ключа
                return new X942.PrivateKey(this, scope, obj, dhPublicKey); 
            }
            if (keyType == API.CKK_DSA) 
            {
                // выполнить преобразование типа
                ANSI.X957.IPublicKey dsaPublicKey = (ANSI.X957.IPublicKey) publicKey; 
            
                // преобразовать тип ключа
                return new X957.PrivateKey(this, scope, obj, dsaPublicKey); 
            }
            if (keyType == API.CKK_EC) 
            {
                // выполнить преобразование типа
                ANSI.X962.IPublicKey ecPublicKey = (ANSI.X962.IPublicKey) publicKey; 

                // в зависимости от области видимости
                CAPI.PKCS11.Applet applet; if (scope is CAPI.PKCS11.Container)
                {
                    // получить используемый апплет
                    applet = ((CAPI.PKCS11.Container)scope).Store; 
                }
                // получить используемый апплет
                else applet = (CAPI.PKCS11.Applet)scope; 
            
                // получить информацию алгоритма
                MechanismInfo info = applet.GetAlgorithmInfo(API.CKM_EC_KEY_PAIR_GEN); 

                // преобразовать тип ключа
                return new X962.PrivateKey(this, scope, obj, ecPublicKey, info.Flags); 
            }
            if (keyType == API.CKK_ECDSA) 
            {
                // выполнить преобразование типа
                ANSI.X962.IPublicKey ecPublicKey = (ANSI.X962.IPublicKey) publicKey; 

                // в зависимости от области видимости
                CAPI.PKCS11.Applet applet; if (scope is CAPI.PKCS11.Container)
                {
                    // получить используемый апплет
                    applet = ((CAPI.PKCS11.Container)scope).Store; 
                }
                // получить используемый апплет
                else applet = (CAPI.PKCS11.Applet)scope; 
            
                // получить информацию алгоритма
                MechanismInfo info = applet.GetAlgorithmInfo(API.CKM_ECDSA_KEY_PAIR_GEN); 

                // преобразовать тип ключа
                return new X962.PrivateKey(this, scope, obj, ecPublicKey, info.Flags); 
            }
            return null; 
        }
	    // атрибуты открытого ключа
	    public override CAPI.PKCS11.Attribute[] PublicKeyAttributes(
            CAPI.PKCS11.Applet applet, IPublicKey publicKey, MechanismInfo info) 
        {
            // в зависимости от типа ключа
            if (publicKey is ANSI.RSA.IPublicKey)
            {
                // выполнить преобразование типа
                ANSI.RSA.IPublicKey rsaPublicKey = (ANSI.RSA.IPublicKey) publicKey; 
            
                // вернуть атрибуты открытого ключа
                return RSA.PublicKey.GetAttributes(this, rsaPublicKey); 
            }
            // в зависимости от типа ключа
            if (publicKey is ANSI.X942.IPublicKey)
            {
                // выполнить преобразование типа
                ANSI.X942.IPublicKey dhPublicKey = (ANSI.X942.IPublicKey) publicKey; 
            
                // вернуть атрибуты открытого ключа
                return X942.PublicKey.GetAttributes(this, dhPublicKey); 
            }
            // в зависимости от типа ключа
            if (publicKey is ANSI.X957.IPublicKey)
            {
                // выполнить преобразование типа
                ANSI.X957.IPublicKey dsaPublicKey = (ANSI.X957.IPublicKey) publicKey; 
            
                // вернуть атрибуты открытого ключа
                return X957.PublicKey.GetAttributes(this, dsaPublicKey); 
            }
            // в зависимости от типа ключа
            if (publicKey is ANSI.X962.IPublicKey)
            {
                // получить информацию алгоритма
                if (info == null) info = applet.GetAlgorithmInfo(API.CKM_EC_KEY_PAIR_GEN); 

                // выполнить преобразование типа
                ANSI.X962.IPublicKey ecPublicKey = (ANSI.X962.IPublicKey) publicKey; 

                // вернуть атрибуты открытого ключа
                return X962.PublicKey.GetAttributes(this, ecPublicKey, info.Flags); 
            }
            return null; 
        }
	    // атрибуты личного ключа
	    public override CAPI.PKCS11.Attribute[] PrivateKeyAttributes(
            CAPI.PKCS11.Applet applet, IPrivateKey privateKey, MechanismInfo info) 
        {
            // в зависимости от типа ключа
            if (privateKey is ANSI.RSA.IPrivateKey)
            {
                // выполнить преобразование типа
                ANSI.RSA.IPrivateKey rsaPrivateKey = (ANSI.RSA.IPrivateKey) privateKey; 
            
                // вернуть атрибуты открытого ключа
                return RSA.PrivateKey.GetAttributes(this, rsaPrivateKey); 
            }
            // в зависимости от типа ключа
            if (privateKey is ANSI.X942.IPrivateKey)
            {
                // выполнить преобразование типа
                ANSI.X942.IPrivateKey dhPrivateKey = (ANSI.X942.IPrivateKey) privateKey; 
            
                // вернуть атрибуты открытого ключа
                return X942.PrivateKey.GetAttributes(this, dhPrivateKey); 
            }
            // в зависимости от типа ключа
            if (privateKey is ANSI.X957.IPrivateKey)
            {
                // выполнить преобразование типа
                ANSI.X957.IPrivateKey dsaPrivateKey = (ANSI.X957.IPrivateKey) privateKey; 
            
                // вернуть атрибуты открытого ключа
                return X957.PrivateKey.GetAttributes(this, dsaPrivateKey); 
            }
            // в зависимости от типа ключа
            if (privateKey is ANSI.X962.IPrivateKey)
            {
                // получить информацию алгоритма
                if (info == null) info = applet.GetAlgorithmInfo(API.CKM_EC_KEY_PAIR_GEN); 

                // выполнить преобразование типа
                ANSI.X962.IPrivateKey ecPrivateKey = (ANSI.X962.IPrivateKey) privateKey; 
            
                // вернуть атрибуты открытого ключа
                return X962.PrivateKey.GetAttributes(this, ecPrivateKey, info.Flags); 
            }
            return null; 
        }
	    // атрибуты симметричного ключа
	    public override CAPI.PKCS11.Attribute[] SecretKeyAttributes(
            SecretKeyFactory keyFactory, int keySize, bool hasValue) 
        { 
            uint type = 0; 
        
            // указать тип ключа
            if (keyFactory is Keys.RC2 ) type = API.CKK_RC2; else 
            if (keyFactory is Keys.RC4 ) type = API.CKK_RC4; else 
            if (keyFactory is Keys.RC5 ) type = API.CKK_RC5; else 
            if (keyFactory is Keys.DES ) type = API.CKK_DES; else 
            if (keyFactory is Keys.AES ) type = API.CKK_AES; else 
            if (keyFactory is Keys.TDES)
            {
                // указать тип ключа
                type = (keySize == 16) ? API.CKK_DES2 : API.CKK_DES3; 
            }
            // проверить поддержку ключа
            if (type != 0) return new CAPI.PKCS11.Attribute[] { CreateAttribute(API.CKA_KEY_TYPE, type) }; 
            
            // вызвать базовую функцию
            return base.SecretKeyAttributes(keyFactory, keySize, hasValue); 
        }
	    // создать алгоритм генерации ключей
	    protected override KeyPairGenerator CreateGenerator(
            CAPI.Factory factory, SecurityObject scope, 
            IRand rand, string keyOID, IParameters parameters) 
        {
            // проверить тип параметров
            if (keyOID == ASN1.ISO.PKCS.PKCS1.OID.rsa)
            {
                // преобразовать тип параметров
                ANSI.RSA.IParameters rsaParameters = ANSI.RSA.Parameters.Convert(parameters);
            
                // указать идентификатор алгоритма
                ulong algID = API.CKM_RSA_PKCS_KEY_PAIR_GEN; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new RSA.KeyPairGenerator(applet, scope, rand, rsaParameters, algID);
                }
                // указать идентификатор алгоритма
                algID = API.CKM_RSA_X9_31_KEY_PAIR_GEN; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 

                    // создать алгоритм генерации ключей
                    return new RSA.KeyPairGenerator(applet, scope, rand, rsaParameters, algID);
                }
            }
            // проверить тип параметров
            if (keyOID == ASN1.ANSI.OID.x942_dh_public_key)
            {
                // преобразовать тип параметров
                ANSI.X942.IParameters dhParameters = (ANSI.X942.IParameters)parameters;
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = FindApplet(scope, API.CKM_X9_42_DH_KEY_PAIR_GEN, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 

                    // создать алгоритм генерации ключей
                    return new X942.KeyPairGenerator(applet, scope, rand, dhParameters);
                }
            }
            // проверить тип параметров
            if (keyOID == ASN1.ANSI.OID.x957_dsa)
            {
                // преобразовать тип параметров
                ANSI.X957.IParameters dsaParameters = (ANSI.X957.IParameters)parameters;
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = FindApplet(scope, API.CKM_DSA_KEY_PAIR_GEN, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 

                    // создать алгоритм генерации ключей
                    return new X957.KeyPairGenerator(applet, scope, rand, dsaParameters);
                }
            }
            // проверить тип параметров
            if (keyOID == ASN1.ANSI.OID.x962_ec_public_key)
            {
                // преобразовать тип параметров
                ANSI.X962.IParameters ecParameters = (ANSI.X962.IParameters)parameters;

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = FindApplet(scope, API.CKM_EC_KEY_PAIR_GEN, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 

                    // создать алгоритм генерации ключей
                    return new X962.KeyPairGenerator(applet, scope, rand, ecParameters); 
                }
            }
            return null; 
        }
	    // создать алгоритм для параметров
	    protected override IAlgorithm CreateAlgorithm(CAPI.Factory factory, 
            SecurityStore scope, string oid, ASN1.IEncodable parameters, Type type)
        {
		    for (int i = 0; i < 1; i++)
            { 
                // для алгоритмов хэширования
                if (type == typeof(CAPI.Hash))
                {
                    // в зависимости от идентификатора
                    if (oid == ASN1.ANSI.OID.rsa_md2) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_MD2); 
                    
                        // создать алгоритм хэширования
                        CAPI.Hash hashAlgorithm = Creator.CreateHash(this, scope, mechanism); 
                    
                        // проверить поддержку алгоритма
                        if (hashAlgorithm == null) break; return hashAlgorithm; 
                    }
                    // в зависимости от идентификатора
                    if (oid == ASN1.ANSI.OID.rsa_md5) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_MD5); 
                    
                        // создать алгоритм хэширования
                        CAPI.Hash hashAlgorithm = Creator.CreateHash(this, scope, mechanism); 
                    
                        // проверить поддержку алгоритма
                        if (hashAlgorithm == null) break; return hashAlgorithm; 
                    }
                    // в зависимости от идентификатора
                    if (oid == ASN1.ANSI.OID.tt_ripemd128) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_RIPEMD128); 
                    
                        // создать алгоритм хэширования
                        CAPI.Hash hashAlgorithm = Creator.CreateHash(this, scope, mechanism); 
                    
                        // проверить поддержку алгоритма
                        if (hashAlgorithm == null) break; return hashAlgorithm; 
                    }
                    // в зависимости от идентификатора
                    if (oid == ASN1.ANSI.OID.tt_ripemd160) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_RIPEMD160); 
                    
                        // создать алгоритм хэширования
                        CAPI.Hash hashAlgorithm = Creator.CreateHash(this, scope, mechanism); 
                    
                        // проверить поддержку алгоритма
                        if (hashAlgorithm == null) break; return hashAlgorithm; 
                    }
                    // в зависимости от идентификатора
                    if (oid == ASN1.ANSI.OID.ssig_sha1) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA_1); 
                    
                        // создать алгоритм хэширования
                        CAPI.Hash hashAlgorithm = Creator.CreateHash(this, scope, mechanism); 
                    
                        // проверить поддержку алгоритма
                        if (hashAlgorithm == null) break; return hashAlgorithm; 
                    }
                    // в зависимости от идентификатора
                    if (oid == ASN1.ANSI.OID.nist_sha2_224) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA224); 
                    
                        // создать алгоритм хэширования
                        CAPI.Hash hashAlgorithm = Creator.CreateHash(this, scope, mechanism); 
                    
                        // проверить поддержку алгоритма
                        if (hashAlgorithm == null) break; return hashAlgorithm; 
                    }
                    // в зависимости от идентификатора
                    if (oid == ASN1.ANSI.OID.nist_sha2_256) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA256); 
                    
                        // создать алгоритм хэширования
                        CAPI.Hash hashAlgorithm = Creator.CreateHash(this, scope, mechanism); 
                    
                        // проверить поддержку алгоритма
                        if (hashAlgorithm == null) break; return hashAlgorithm; 
                    }
                    // в зависимости от идентификатора
                    if (oid == ASN1.ANSI.OID.nist_sha2_384) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA384); 
                    
                        // создать алгоритм хэширования
                        CAPI.Hash hashAlgorithm = Creator.CreateHash(this, scope, mechanism); 
                    
                        // проверить поддержку алгоритма
                        if (hashAlgorithm == null) break; return hashAlgorithm; 
                    }
                    // в зависимости от идентификатора
                    if (oid == ASN1.ANSI.OID.nist_sha2_512) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA512); 
                    
                        // создать алгоритм хэширования
                        CAPI.Hash hashAlgorithm = Creator.CreateHash(this, scope, mechanism); 
                    
                        // проверить поддержку алгоритма
                        if (hashAlgorithm == null) break; return hashAlgorithm; 
                    }
                    if (oid == ASN1.ANSI.OID.nist_sha2_512_224) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA512_224); 
                    
                        // создать алгоритм хэширования
                        CAPI.Hash hashAlgorithm = Creator.CreateHash(this, scope, mechanism); 
                    
                        // проверить поддержку алгоритма
                        if (hashAlgorithm == null) break; return hashAlgorithm; 
                    }
                    if (oid == ASN1.ANSI.OID.nist_sha2_512_256) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA512_256); 
                    
                        // создать алгоритм хэширования
                        CAPI.Hash hashAlgorithm = Creator.CreateHash(this, scope, mechanism); 
                    
                        // проверить поддержку алгоритма
                        if (hashAlgorithm == null) break; return hashAlgorithm; 
                    }
                    // в зависимости от идентификатора
                    if (oid == ASN1.ANSI.OID.nist_sha3_224) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA3_224); 
                    
                        // создать алгоритм хэширования
                        CAPI.Hash hashAlgorithm = Creator.CreateHash(this, scope, mechanism); 
                    
                        // проверить поддержку алгоритма
                        if (hashAlgorithm == null) break; return hashAlgorithm; 
                    }
                    // в зависимости от идентификатора
                    if (oid == ASN1.ANSI.OID.nist_sha3_256) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA3_256); 
                    
                        // создать алгоритм хэширования
                        CAPI.Hash hashAlgorithm = Creator.CreateHash(this, scope, mechanism); 
                    
                        // проверить поддержку алгоритма
                        if (hashAlgorithm == null) break; return hashAlgorithm; 
                    }
                    // в зависимости от идентификатора
                    if (oid == ASN1.ANSI.OID.nist_sha3_384) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA3_384); 
                    
                        // создать алгоритм хэширования
                        CAPI.Hash hashAlgorithm = Creator.CreateHash(this, scope, mechanism); 
                    
                        // проверить поддержку алгоритма
                        if (hashAlgorithm == null) break; return hashAlgorithm; 
                    }
                    // в зависимости от идентификатора
                    if (oid == ASN1.ANSI.OID.nist_sha3_512) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA3_512); 
                    
                        // создать алгоритм хэширования
                        CAPI.Hash hashAlgorithm = Creator.CreateHash(this, scope, mechanism); 
                    
                        // проверить поддержку алгоритма
                        if (hashAlgorithm == null) break; return hashAlgorithm; 
                    }
                }
                // для алгоритмов выработки имитовставки
                else if (type == typeof(Mac))
                {    
			        if (oid == ASN1.ANSI.OID.ssig_des_mac)
                    {
                        // раскодировать размер имитовставки
                        ASN1.Integer bits = new ASN1.Integer(parameters); 
                
                        // проверить корректность размера
                        if ((bits.Value.IntValue % 8) != 0) break; 
                
                        // определить размер имитовставки
                        int macSize = bits.Value.IntValue / 8; if (macSize == 4)
                        {
                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(API.CKM_DES_MAC); 
                        
                            // создать алгоритм вычисления имитовставки
                            CAPI.Mac macAlgorithm = Creator.CreateMac(this, scope, mechanism, 0);

                            // проверить поддержку алгоритма
                            if (macAlgorithm == null) break; return macAlgorithm; 
                        }
                        else { 
                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(API.CKM_DES_MAC_GENERAL, macSize); 
                        
                            // создать алгоритм вычисления имитовставки
                            CAPI.Mac macAlgorithm = Creator.CreateMac(this, scope, mechanism, 0);

                            // проверить поддержку алгоритма
                            if (macAlgorithm == null) break; return macAlgorithm; 
                        }
                    }
			        if (oid == ASN1.ANSI.OID.ipsec_hmac_md5)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_MD5_HMAC); 
                        
                        // создать алгоритм вычисления имитовставки
                        CAPI.Mac macAlgorithm = Creator.CreateMac(this, scope, mechanism, 0);

                        // проверить поддержку алгоритма
                        if (macAlgorithm == null) break; return macAlgorithm; 
                    }
			        if (oid == ASN1.ANSI.OID.ipsec_hmac_ripemd160)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_RIPEMD160_HMAC); 
                        
                        // создать алгоритм вычисления имитовставки
                        CAPI.Mac macAlgorithm = Creator.CreateMac(this, scope, mechanism, 0);

                        // проверить поддержку алгоритма
                        if (macAlgorithm == null) break; return macAlgorithm; 
                    }
			        if (oid == ASN1.ANSI.OID.rsa_hmac_sha1)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA_1_HMAC); 
                        
                        // создать алгоритм вычисления имитовставки
                        CAPI.Mac macAlgorithm = Creator.CreateMac(this, scope, mechanism, 0);

                        // проверить поддержку алгоритма
                        if (macAlgorithm == null) break; return macAlgorithm; 
                    }
			        if (oid == ASN1.ANSI.OID.rsa_hmac_sha2_224)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA224_HMAC); 
                        
                        // создать алгоритм вычисления имитовставки
                        CAPI.Mac macAlgorithm = Creator.CreateMac(this, scope, mechanism, 0);

                        // проверить поддержку алгоритма
                        if (macAlgorithm == null) break; return macAlgorithm; 
                    }
			        if (oid  == ASN1.ANSI.OID.rsa_hmac_sha2_256)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA256_HMAC); 
                        
                        // создать алгоритм вычисления имитовставки
                        CAPI.Mac macAlgorithm = Creator.CreateMac(this, scope, mechanism, 0);

                        // проверить поддержку алгоритма
                        if (macAlgorithm == null) break; return macAlgorithm; 
                    }
			        if (oid  == ASN1.ANSI.OID.rsa_hmac_sha2_384)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA384_HMAC); 
                        
                        // создать алгоритм вычисления имитовставки
                        CAPI.Mac macAlgorithm = Creator.CreateMac(this, scope, mechanism, 0);

                        // проверить поддержку алгоритма
                        if (macAlgorithm == null) break; return macAlgorithm; 
                    }
			        if (oid  == ASN1.ANSI.OID.rsa_hmac_sha2_512)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA512_HMAC); 
                        
                        // создать алгоритм вычисления имитовставки
                        CAPI.Mac macAlgorithm = Creator.CreateMac(this, scope, mechanism, 0);

                        // проверить поддержку алгоритма
                        if (macAlgorithm == null) break; return macAlgorithm; 
                    }
			        if (oid  == ASN1.ANSI.OID.rsa_hmac_sha2_512_224)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA512_224_HMAC); 
                        
                        // создать алгоритм вычисления имитовставки
                        CAPI.Mac macAlgorithm = Creator.CreateMac(this, scope, mechanism, 0);

                        // проверить поддержку алгоритма
                        if (macAlgorithm == null) break; return macAlgorithm; 
                    }
			        if (oid  == ASN1.ANSI.OID.rsa_hmac_sha2_512_256)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA512_256_HMAC); 
                        
                        // создать алгоритм вычисления имитовставки
                        CAPI.Mac macAlgorithm = Creator.CreateMac(this, scope, mechanism, 0);

                        // проверить поддержку алгоритма
                        if (macAlgorithm == null) break; return macAlgorithm; 
                    }
                }
                // для алгоритмов симметричного шифрования
                else if (type == typeof(CAPI.Cipher))
                {
                    if (oid == ASN1.ANSI.OID.rsa_rc2_ecb)
                    { 
                        // проверить указание параметров алгоритма
                        int keyBits = 32; if (!ASN1.Encodable.IsNullOrEmpty(parameters))
                        { 
                            // раскодировать параметры алгоритма
                            ASN1.Integer version = new ASN1.Integer(parameters);

                            // определить число битов
                            keyBits = ASN1.ANSI.RSA.RC2ParameterVersion.GetKeyBits(version); 
                        }
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_RC2_ECB, keyBits); 

                        // создать алгоритм шифрования
                        using (CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 0))
                        {
                            // проверить поддержку алгоритма
                            if (cipher == null) return null; 
                    
                            // изменить режим дополнения
                            return new BlockMode.PaddingConverter(cipher, PaddingMode.Any);
                        }
                    }
                    if (oid == ASN1.ANSI.OID.rsa_rc4) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_RC4); 
                    
                        // создать алгоритм шифрования
                        CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 0); 

                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
                    }
                    if (oid == ASN1.ANSI.OID.rsa_rc5_cbc)
                    {
                        // раскодировать параметры алгоритма
                        ASN1.ANSI.RSA.RC5CBCParameter cipherParameters = 
                            new ASN1.ANSI.RSA.RC5CBCParameter(parameters);
                
                        // определить размер блока
                        int blockSize = cipherParameters.BlockSize.Value.IntValue; 

                        // определить число раундов
                        int rounds = cipherParameters.Rounds.Value.IntValue; 

                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_RC5_CBC, 
                            new Parameters.CK_RC5_CBC_PARAMS(
                                blockSize / 2, rounds, cipherParameters.IV.Value
                        )); 
                        // создать алгоритм шифрования
                        CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 0); 

                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
                    }
                    if (oid == ASN1.ANSI.OID.rsa_rc5_cbc_pad)
                    {
                        // раскодировать параметры алгоритма
                        ASN1.ANSI.RSA.RC5CBCParameter cipherParameters = 
                            new ASN1.ANSI.RSA.RC5CBCParameter(parameters);
                
                        // определить размер блока
                        int blockSize = cipherParameters.BlockSize.Value.IntValue; 

                        // определить число раундов
                        int rounds = cipherParameters.Rounds.Value.IntValue; 

                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_RC5_CBC_PAD, 
                            new Parameters.CK_RC5_CBC_PARAMS(
                                blockSize / 2, rounds, cipherParameters.IV.Value
                        )); 
                        // создать алгоритм шифрования
                        CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 0); 

                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
                    }
			        if (oid == ASN1.ANSI.OID.ssig_des_ecb) 
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DES_ECB); 

                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 0))
                        {
                            // проверить поддержку алгоритма
                            if (cipher == null) break; 
                    
                            // изменить режим дополнения
                            return new BlockMode.PaddingConverter(cipher, PaddingMode.Any);
                        }
                    }
                    if (oid == ASN1.ANSI.OID.tt_des_ecb) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DES_ECB); 

                        // создать алгоритм шифрования блока
                        CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 0);

                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
                    }
			        if (oid == ASN1.ANSI.OID.tt_des_ecb_pad) 
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DES_ECB); 

                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 0))
                        {
                            // проверить поддержку алгоритма
                            if (cipher == null) break; 
                    
                            // изменить режим дополнения
                            return new BlockMode.PaddingConverter(cipher, PaddingMode.PKCS5);
                        }
			        }
			        if (oid == ASN1.ANSI.OID.ssig_des_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.OctetString iv = new ASN1.OctetString(parameters); 
                
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DES_CBC, iv.Value); 

                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 0))
                        {
                            // проверить поддержку алгоритма
                            if (cipher == null) break; 
                    
                            // изменить режим дополнения
                            return new BlockMode.PaddingConverter(cipher, PaddingMode.Any);
                        }
			        }
			        if (oid == ASN1.ANSI.OID.tt_des_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.OctetString iv = new ASN1.OctetString(parameters); 
                
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DES_CBC, iv.Value); 

                        // создать алгоритм шифрования блока
                        CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 0); 

                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
			        }
			        if (oid == ASN1.ANSI.OID.tt_des_cbc_pad) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.OctetString iv = new ASN1.OctetString(parameters); 
                
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DES_CBC_PAD, iv.Value); 

                        // создать алгоритм шифрования блока
                        CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 0); 

                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
			        }
			        if (oid == ASN1.ANSI.OID.ssig_des_ofb) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ANSI.FBParameter cipherParameters = 
                            new ASN1.ANSI.FBParameter(parameters); 
                
                        // проверить корректность параметров
                        if (cipherParameters.NumberOfBits.Value.IntValue == 64)
                        { 
                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(
                                API.CKM_DES_OFB64, cipherParameters.IV.Value
                            ); 
                            // создать алгоритм шифрования
                            CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 0); 

                            // проверить поддержку алгоритма
                            if (cipher == null) break; return cipher; 
                        }
                        // проверить корректность параметров
                        if (cipherParameters.NumberOfBits.Value.IntValue == 8)
                        { 
                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(
                                API.CKM_DES_OFB8, cipherParameters.IV.Value
                            ); 
                            // создать алгоритм шифрования
                            CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 0); 

                            // проверить поддержку алгоритма
                            if (cipher == null) break; return cipher; 
                        }
                        break; 
			        }
			        if (oid == ASN1.ANSI.OID.ssig_des_cfb) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ANSI.FBParameter cipherParameters = 
                            new ASN1.ANSI.FBParameter(parameters); 
                
                        // проверить корректность параметров
                        if (cipherParameters.NumberOfBits.Value.IntValue == 64)
                        { 
                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(
                                API.CKM_DES_CFB64, cipherParameters.IV.Value
                            ); 
                            // создать алгоритм шифрования
                            CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 0); 

                            // проверить поддержку алгоритма
                            if (cipher == null) break; return cipher; 
                        }
                        // проверить корректность параметров
                        if (cipherParameters.NumberOfBits.Value.IntValue == 8)
                        { 
                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(
                                API.CKM_DES_CFB8, cipherParameters.IV.Value
                            ); 
                            // создать алгоритм шифрования
                            CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 0); 

                            // проверить поддержку алгоритма
                            if (cipher == null) break; return cipher; 
                        }
                        break; 
			        }
			        if (oid == ASN1.ANSI.OID.ssig_tdes_ecb)
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DES3_ECB); 

                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 0))
                        {
                            // проверить поддержку алгоритма
                            if (cipher == null) break; 
                    
                            // изменить режим дополнения
                            return new BlockMode.PaddingConverter(cipher, PaddingMode.Any);
                        }
                    }
			        if (oid == ASN1.ANSI.OID.tt_tdes192_ecb)
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DES3_ECB); 

                        // создать алгоритм шифрования блока
                        CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 24); 

                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
			        }
			        if (oid == ASN1.ANSI.OID.rsa_tdes192_cbc) 
			        {
                        // раскодировать параметры алгоритма
                        ASN1.OctetString iv = new ASN1.OctetString(parameters); 

                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DES3_CBC, iv.Value); 

                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 24))
                        {
                            // проверить поддержку алгоритма
                            if (cipher == null) break; 
                    
                            // изменить режим дополнения
                            return new BlockMode.PaddingConverter(cipher, PaddingMode.Any);
                        }
			        }
			        if (oid == ASN1.ANSI.OID.tt_tdes192_cbc) 
			        {
                        // раскодировать параметры алгоритма
                        ASN1.OctetString iv = new ASN1.OctetString(parameters); 

                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DES3_CBC, iv.Value); 

                        // создать алгоритм шифрования блока
                        CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 24); 

                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
			        }
			        if (oid == ASN1.ANSI.OID.tt_tdes192_cbc_pad) 
			        {
                        // раскодировать параметры алгоритма
                        ASN1.OctetString iv = new ASN1.OctetString(parameters); 

                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DES3_CBC_PAD, iv.Value); 

                        // создать алгоритм шифрования блока
                        CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 24); 

                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
			        }
			        if (oid == ASN1.ANSI.OID.nist_aes128_ecb)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_AES_ECB); 

                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 16))
                        {
                            // проверить поддержку алгоритма
                            if (cipher == null) break; 
                    
                            // изменить режим дополнения
                            return new BlockMode.PaddingConverter(cipher, PaddingMode.Any);
                        }
                    }
			        if (oid == ASN1.ANSI.OID.nist_aes128_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.OctetString iv = new ASN1.OctetString(parameters); 

                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_AES_CBC, iv.Value); 

                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 16))
                        {
                            // проверить поддержку алгоритма
                            if (cipher == null) break; 
                    
                            // изменить режим дополнения
                            return new BlockMode.PaddingConverter(cipher, PaddingMode.Any);
                        }
			        }
			        if (oid == ASN1.ANSI.OID.nist_aes128_cfb) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ANSI.FBParameter cipherParameters = 
                            new ASN1.ANSI.FBParameter(parameters); 
                
                        // проверить корректность параметров
                        if (cipherParameters.NumberOfBits.Value.IntValue == 128)
                        { 
                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(
                                API.CKM_AES_CFB128, cipherParameters.IV.Value
                            ); 
                            // создать алгоритм шифрования блока
                            CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 16); 

                            // проверить поддержку алгоритма
                            if (cipher == null) break; return cipher; 
                        }
                        // проверить корректность параметров
                        if (cipherParameters.NumberOfBits.Value.IntValue == 64)
                        { 
                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(
                                API.CKM_AES_CFB64, cipherParameters.IV.Value
                            ); 
                            // создать алгоритм шифрования блока
                            CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 16); 

                            // проверить поддержку алгоритма
                            if (cipher == null) break; return cipher; 
                        }
                        // проверить корректность параметров
                        if (cipherParameters.NumberOfBits.Value.IntValue == 8)
                        { 
                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(
                                API.CKM_AES_CFB8, cipherParameters.IV.Value
                            ); 
                            // создать алгоритм шифрования блока
                            CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 16); 

                            // проверить поддержку алгоритма
                            if (cipher == null) break; return cipher; 
                        }
                        // проверить корректность параметров
                        if (cipherParameters.NumberOfBits.Value.IntValue == 1)
                        { 
                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(
                                API.CKM_AES_CFB1, cipherParameters.IV.Value
                            ); 
                            // создать алгоритм шифрования блока
                            CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 16); 

                            // проверить поддержку алгоритма
                            if (cipher == null) break; return cipher; 
                        }
                        break; 
			        }
			        if (oid == ASN1.ANSI.OID.nist_aes128_ofb) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ANSI.FBParameter cipherParameters = 
                            new ASN1.ANSI.FBParameter(parameters); 
                
                        // проверить корректность параметров
                        if (cipherParameters.NumberOfBits.Value.IntValue == 128)
                        { 
                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(
                                API.CKM_AES_OFB, cipherParameters.IV.Value
                            ); 
                            // создать алгоритм шифрования блока
                            CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 16); 

                            // проверить поддержку алгоритма
                            if (cipher == null) break; return cipher; 
                        }
                        break; 
			        }
			        if (oid == ASN1.ANSI.OID.nist_aes192_ecb)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_AES_ECB); 

                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 24))
                        {
                            // проверить поддержку алгоритма
                            if (cipher == null) break; 
                    
                            // изменить режим дополнения
                            return new BlockMode.PaddingConverter(cipher, PaddingMode.Any);
                        }
                    }
			        if (oid == ASN1.ANSI.OID.nist_aes192_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.OctetString iv = new ASN1.OctetString(parameters); 

                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_AES_CBC, iv.Value); 

                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 24))
                        {
                            // проверить поддержку алгоритма
                            if (cipher == null) break; 
                    
                            // изменить режим дополнения
                            return new BlockMode.PaddingConverter(cipher, PaddingMode.Any);
                        }
			        }
			        if (oid == ASN1.ANSI.OID.nist_aes192_cfb) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ANSI.FBParameter cipherParameters = 
                            new ASN1.ANSI.FBParameter(parameters); 
                
                        // проверить корректность параметров
                        if (cipherParameters.NumberOfBits.Value.IntValue == 128)
                        { 
                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(
                                API.CKM_AES_CFB128, cipherParameters.IV.Value
                            ); 
                            // создать алгоритм шифрования блока
                            CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 24); 

                            // проверить поддержку алгоритма
                            if (cipher == null) break; return cipher; 
                        }
                        // проверить корректность параметров
                        if (cipherParameters.NumberOfBits.Value.IntValue == 64)
                        { 
                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(
                                API.CKM_AES_CFB64, cipherParameters.IV.Value
                            ); 
                            // создать алгоритм шифрования блока
                            CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 24); 

                            // проверить поддержку алгоритма
                            if (cipher == null) break; return cipher; 
                        }
                        // проверить корректность параметров
                        if (cipherParameters.NumberOfBits.Value.IntValue == 8)
                        { 
                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(
                                API.CKM_AES_CFB8, cipherParameters.IV.Value
                            ); 
                            // создать алгоритм шифрования блока
                            CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 24); 

                            // проверить поддержку алгоритма
                            if (cipher == null) break; return cipher; 
                        }
                        // проверить корректность параметров
                        if (cipherParameters.NumberOfBits.Value.IntValue == 1)
                        { 
                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(
                                API.CKM_AES_CFB1, cipherParameters.IV.Value
                            ); 
                            // создать алгоритм шифрования блока
                            CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 24); 

                            // проверить поддержку алгоритма
                            if (cipher == null) break; return cipher; 
                        }
                        break; 
			        }
			        if (oid == ASN1.ANSI.OID.nist_aes192_ofb) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ANSI.FBParameter cipherParameters = 
                            new ASN1.ANSI.FBParameter(parameters); 
                
                        // проверить корректность параметров
                        if (cipherParameters.NumberOfBits.Value.IntValue == 128)
                        { 
                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(
                                API.CKM_AES_OFB, cipherParameters.IV.Value
                            ); 
                            // создать алгоритм шифрования блока
                            CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 24); 

                            // проверить поддержку алгоритма
                            if (cipher == null) break; return cipher; 
                        }
                        break; 
			        }
			        if (oid == ASN1.ANSI.OID.nist_aes256_ecb)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_AES_ECB); 

                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 32))
                        {
                            // проверить поддержку алгоритма
                            if (cipher == null) break; 
                    
                            // изменить режим дополнения
                            return new BlockMode.PaddingConverter(cipher, PaddingMode.Any);
                        }
                    }
			        if (oid == ASN1.ANSI.OID.nist_aes256_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.OctetString iv = new ASN1.OctetString(parameters); 

                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_AES_CBC, iv.Value); 

                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 32))
                        {
                            // проверить поддержку алгоритма
                            if (cipher == null) break; 
                    
                            // изменить режим дополнения
                            return new BlockMode.PaddingConverter(cipher, PaddingMode.Any);
                        }
			        }
			        if (oid == ASN1.ANSI.OID.nist_aes256_cfb) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ANSI.FBParameter cipherParameters = 
                            new ASN1.ANSI.FBParameter(parameters); 
                
                        // проверить корректность параметров
                        if (cipherParameters.NumberOfBits.Value.IntValue == 128)
                        { 
                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(
                                API.CKM_AES_CFB128, cipherParameters.IV.Value
                            ); 
                            // создать алгоритм шифрования блока
                            CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 32); 

                            // проверить поддержку алгоритма
                            if (cipher == null) break; return cipher; 
                        }
                        // проверить корректность параметров
                        if (cipherParameters.NumberOfBits.Value.IntValue == 64)
                        { 
                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(
                                API.CKM_AES_CFB64, cipherParameters.IV.Value
                            ); 
                            // создать алгоритм шифрования блока
                            CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 32); 

                            // проверить поддержку алгоритма
                            if (cipher == null) break; return cipher; 
                        }
                        // проверить корректность параметров
                        if (cipherParameters.NumberOfBits.Value.IntValue == 8)
                        { 
                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(
                                API.CKM_AES_CFB8, cipherParameters.IV.Value
                            ); 
                            // создать алгоритм шифрования блока
                            CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 32); 

                            // проверить поддержку алгоритма
                            if (cipher == null) break; return cipher; 
                        }
                        // проверить корректность параметров
                        if (cipherParameters.NumberOfBits.Value.IntValue == 1)
                        { 
                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(
                                API.CKM_AES_CFB1, cipherParameters.IV.Value
                            ); 
                            // создать алгоритм шифрования блока
                            CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 32); 

                            // проверить поддержку алгоритма
                            if (cipher == null) break; return cipher; 
                        }
                        break; 
			        }
			        if (oid == ASN1.ANSI.OID.nist_aes256_ofb) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ANSI.FBParameter cipherParameters = 
                            new ASN1.ANSI.FBParameter(parameters); 
                
                        // проверить корректность параметров
                        if (cipherParameters.NumberOfBits.Value.IntValue == 128)
                        { 
                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(
                                API.CKM_AES_OFB, cipherParameters.IV.Value
                            ); 
                            // создать алгоритм шифрования блока
                            CAPI.Cipher cipher = Creator.CreateCipher(this, scope, mechanism, 32); 

                            // проверить поддержку алгоритма
                            if (cipher == null) break; return cipher; 
                        }
                        break; 
			        }
			        // для алгоритмов шифрования по паролю
			        if (oid == ASN1.ISO.PKCS.PKCS5.OID.pbe_md2_des_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBEParameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters);

                        // указать идентификатор алгоритма
                        ulong algID = API.CKM_PBE_MD2_DES_CBC; 
                
                        // найти подходящую смарт-карту
                        using (CAPI.PKCS11.Applet applet = FindApplet(scope, algID, 0, 0))
                        {
                            // проверить наличие смарт-карты
                            if (applet == null) break; 

                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(API.CKM_DES_CBC_PAD, new byte[8]);
                    
                            // получить алгоритм шифрования
                            using (CAPI.Cipher cipher = Creator.CreateCipher(
                                this, scope, mechanism, 0))
                            {
                                // проверить наличие алгоритма
                                if (cipher == null) break; 
                            }                            
                            // создать алгоритм шифрования по паролю
                            return new PBE.PBES1_DES_CBC(
                                applet, algID, pbeParameters.Salt.Value, 
                                pbeParameters.IterationCount.Value.IntValue
                            ); 
                        }
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS5.OID.pbe_md5_des_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBEParameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters);
                
                        // указать идентификатор алгоритма
                        ulong algID = API.CKM_PBE_MD5_DES_CBC; 

                        // найти подходящую смарт-карту
                        using (CAPI.PKCS11.Applet applet = FindApplet(scope, algID, 0, 0))
                        {
                            // проверить наличие смарт-карты
                            if (applet == null) break; 

                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(API.CKM_DES_CBC_PAD, new byte[8]);
                    
                            // получить алгоритм шифрования
                            using (CAPI.Cipher cipher = Creator.CreateCipher(
                                this, scope, mechanism, 0))
                            {
                                // проверить наличие алгоритма
                                if (cipher == null) break; 
                            }                            
                            // создать алгоритм шифрования по паролю
                            return new PBE.PBES1_DES_CBC(
                                applet, algID, pbeParameters.Salt.Value, 
                                pbeParameters.IterationCount.Value.IntValue
                            ); 
                        }
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS12.OID.pbe_sha1_rc4_128) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBEParameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters);
                
                        // указать идентификатор алгоритма
                        ulong algID = API.CKM_PBE_SHA1_RC4_128; 

                        // найти подходящую смарт-карту
                        using (CAPI.PKCS11.Applet applet = FindApplet(scope, algID, 0, 0))
                        {
                            // проверить наличие смарт-карты
                            if (applet == null) break; 
                            
                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(API.CKM_RC4); 
                    
                            // получить алгоритм шифрования
                            using (CAPI.Cipher cipher = Creator.CreateCipher(
                                this, scope, mechanism, 16))
                            {
                                // проверить наличие алгоритма
                                if (cipher == null) break; 
                            }                            
                            // создать алгоритм шифрования по паролю
                            return new PBE.PBESP12_RC4(
                                applet, algID, pbeParameters.Salt.Value, 
                                pbeParameters.IterationCount.Value.IntValue
                            ); 
                        }
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS12.OID.pbe_sha1_rc4_40) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBEParameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters);
                
                        // указать идентификатор алгоритма
                        ulong algID = API.CKM_PBE_SHA1_RC4_40; 

                        // найти подходящую смарт-карту
                        using (CAPI.PKCS11.Applet applet = FindApplet(scope, algID, 0, 0))
                        {
                            // проверить наличие смарт-карты
                            if (applet == null) break; 
                            
                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(API.CKM_RC4); 
                    
                            // получить алгоритм шифрования
                            using (CAPI.Cipher cipher = Creator.CreateCipher(
                                this, scope, mechanism, 5))
                            {
                                // проверить наличие алгоритма
                                if (cipher == null) break; 
                            }                            
                            // создать алгоритм шифрования по паролю
                            return new PBE.PBESP12_RC4(
                                applet, algID, pbeParameters.Salt.Value, 
                                pbeParameters.IterationCount.Value.IntValue
                            ); 
                        }
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS12.OID.pbe_sha1_rc2_128_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBEParameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters);
                
                        // указать идентификатор алгоритма
                        ulong algID = API.CKM_PBE_SHA1_RC2_128_CBC; 

                        // найти подходящую смарт-карту
                        using (CAPI.PKCS11.Applet applet = FindApplet(scope, algID, 0, 0))
                        {
                            // проверить наличие смарт-карты
                            if (applet == null) break; 

                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(API.CKM_RC2_CBC_PAD, 
                                new Parameters.CK_RC2_CBC_PARAMS(128, new byte[8])
                            );
                            // получить алгоритм шифрования
                            using (CAPI.Cipher cipher = Creator.CreateCipher(
                                this, scope, mechanism, 16))
                            {
                                // проверить наличие алгоритма
                                if (cipher == null) break; 
                            }                            
                            // создать алгоритм шифрования по паролю
                            return new PBE.PBESP12_RC2_CBC(
                                applet, algID, pbeParameters.Salt.Value, 
                                pbeParameters.IterationCount.Value.IntValue
                            ); 
                        }
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS12.OID.pbe_sha1_rc2_40_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBEParameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters);
                
                        // указать идентификатор алгоритма
                        ulong algID = API.CKM_PBE_SHA1_RC2_40_CBC; 

                        // найти подходящую смарт-карту
                        using (CAPI.PKCS11.Applet applet = FindApplet(scope, algID, 0, 0))
                        {
                            // проверить наличие смарт-карты
                            if (applet == null) break; 

                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(API.CKM_RC2_CBC_PAD, 
                                new Parameters.CK_RC2_CBC_PARAMS(40, new byte[8])
                            );
                            // получить алгоритм шифрования
                            using (CAPI.Cipher cipher = Creator.CreateCipher(
                                this, scope, mechanism, 5))
                            {
                                // проверить наличие алгоритма
                                if (cipher == null) break; 
                            }                            
                            // создать алгоритм шифрования по паролю
                            return new PBE.PBESP12_RC2_CBC(
                                applet, algID, pbeParameters.Salt.Value, 
                                pbeParameters.IterationCount.Value.IntValue
                            ); 
                        }
                    }
			        if (oid == ASN1.ISO.PKCS.PKCS12.OID.pbe_sha1_tdes_192_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBEParameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters);
                
                        // указать идентификатор алгоритма
                        ulong algID = API.CKM_PBE_SHA1_DES3_EDE_CBC; 

                        // найти подходящую смарт-карту
                        using (CAPI.PKCS11.Applet applet = FindApplet(scope, algID, 0, 0))
                        {
                            // проверить наличие смарт-карты
                            if (applet == null) break; 

                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(API.CKM_DES3_CBC_PAD, new byte[8]);
                    
                            // получить алгоритм шифрования
                            using (CAPI.Cipher cipher = Creator.CreateCipher(
                                this, scope, mechanism, 24))
                            {
                                // проверить наличие алгоритма
                                if (cipher == null) break; 
                            }                            
                            // создать алгоритм шифрования по паролю
                            return new PBE.PBESP12_TDES192_CBC(
                                applet, algID, pbeParameters.Salt.Value, 
                                pbeParameters.IterationCount.Value.IntValue
                            ); 
                        }
                    }
			        if (oid == ASN1.ISO.PKCS.PKCS12.OID.pbe_sha1_tdes_128_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBEParameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters);
                
                        // указать идентификатор алгоритма
                        ulong algID = API.CKM_PBE_SHA1_DES2_EDE_CBC; 

                        // найти подходящую смарт-карту
                        using (CAPI.PKCS11.Applet applet = FindApplet(scope, algID, 0, 0))
                        {
                            // проверить наличие смарт-карты
                            if (applet == null) break; 

                            // указать параметры алгоритма
                            Mechanism mechanism = new Mechanism(API.CKM_DES3_CBC_PAD, new byte[8]);
                    
                            // получить алгоритм шифрования
                            using (CAPI.Cipher cipher = Creator.CreateCipher(
                                this, scope, mechanism, 16))
                            {
                                // проверить наличие алгоритма
                                if (cipher == null) break; 
                            }                            
                            // создать алгоритм шифрования по паролю
                            return new PBE.PBESP12_TDES128_CBC(
                                applet, algID, pbeParameters.Salt.Value, 
                                pbeParameters.IterationCount.Value.IntValue
                            ); 
                        }
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

                        // инициализировать переменнные
                        ulong prf = 0; int keySize = -1;

		                // при указании размера ключа
		                if (pbeParameters.KeyLength != null)
                        {
			                // прочитать размер ключа
			                keySize = pbeParameters.KeyLength.Value.IntValue;
		                }
                        // определить идентификатор алгоритма вычисления имитовставки
                        string hmacOID = pbeParameters.PRF.Algorithm.Value; 

                        if (hmacOID == ASN1.ANSI.OID.rsa_hmac_sha1) 
                        {
                            // преобразовать идентификатор алгоритма вычисления имитовставки
                            prf = API.CKP_PKCS5_PBKD2_HMAC_SHA1; 
                        }
                        else if (hmacOID == ASN1.ANSI.OID.rsa_hmac_sha2_224) 
                        {
                            // преобразовать идентификатор алгоритма вычисления имитовставки
                            prf = API.CKP_PKCS5_PBKD2_HMAC_SHA224; 
                        }
                        else if (hmacOID == ASN1.ANSI.OID.rsa_hmac_sha2_256) 
                        {    
                            // преобразовать идентификатор алгоритма вычисления имитовставки
                            prf = API.CKP_PKCS5_PBKD2_HMAC_SHA256; 
                        }
                        else if (hmacOID == ASN1.ANSI.OID.rsa_hmac_sha2_384) 
                        {
                            // преобразовать идентификатор алгоритма вычисления имитовставки
                            prf = API.CKP_PKCS5_PBKD2_HMAC_SHA384;
                        }
                        else if (hmacOID == ASN1.ANSI.OID.rsa_hmac_sha2_512) 
                        {
                            // преобразовать идентификатор алгоритма вычисления имитовставки
                            prf = API.CKP_PKCS5_PBKD2_HMAC_SHA512;
                        }
                        // извлечь salt-значение
                        else break; ASN1.OctetString salt = new ASN1.OctetString(pbeParameters.Salt); 
                        
                        // создать алгоритм наследования ключа
                        KeyDerive keyDerive = Creator.CreateDerivePBKDF2(
                            this, scope, PBKDF2ParametersType, prf, salt.Value, 
                            pbeParameters.IterationCount.Value.IntValue, keySize
                        ); 
                        // проверить поддержку алгоритма
                        if (keyDerive == null) break; return keyDerive; 
				    }
			    }
                // для алгоритмов шифрования ключа
                else if (type == typeof(KeyWrap))
                {
                    if (oid == ASN1.ANSI.OID.nist_aes128_wrap) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_AES_KEY_WRAP); 
                    
                        // создать алгоритм 
                        KeyWrap keyWrap = Creator.CreateKeyWrap(this, scope, mechanism, 16);   
                    
                        // проверить поддержку алгоритма
                        if (keyWrap == null) break; return keyWrap; 
                    }
                    if (oid == ASN1.ANSI.OID.nist_aes128_wrap_pad) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_AES_KEY_WRAP_PAD); 
                    
                        // создать алгоритм 
                        KeyWrap keyWrap = Creator.CreateKeyWrap(this, scope, mechanism, 16);   
                    
                        // проверить поддержку алгоритма
                        if (keyWrap == null) break; return keyWrap; 
                    }
                    if (oid == ASN1.ANSI.OID.nist_aes192_wrap) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_AES_KEY_WRAP); 
                    
                        // создать алгоритм 
                        KeyWrap keyWrap = Creator.CreateKeyWrap(this, scope, mechanism, 24);   
                    
                        // проверить поддержку алгоритма
                        if (keyWrap == null) break; return keyWrap; 
                    }
                    if (oid == ASN1.ANSI.OID.nist_aes192_wrap_pad) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_AES_KEY_WRAP_PAD); 
                    
                        // создать алгоритм 
                        KeyWrap keyWrap = Creator.CreateKeyWrap(this, scope, mechanism, 24);   
                    
                        // проверить поддержку алгоритма
                        if (keyWrap == null) break; return keyWrap; 
                    }
                    if (oid == ASN1.ANSI.OID.nist_aes256_wrap) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_AES_KEY_WRAP); 
                    
                        // создать алгоритм 
                        KeyWrap keyWrap = Creator.CreateKeyWrap(this, scope, mechanism, 32);   
                    
                        // проверить поддержку алгоритма
                        if (keyWrap == null) break; return keyWrap; 
                    }
                    if (oid == ASN1.ANSI.OID.nist_aes256_wrap_pad) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_AES_KEY_WRAP_PAD); 
                    
                        // создать алгоритм 
                        KeyWrap keyWrap = Creator.CreateKeyWrap(this, scope, mechanism, 32);   
                    
                        // проверить поддержку алгоритма
                        if (keyWrap == null) break; return keyWrap; 
                    }
                }
                // для алгоритмов асимметричного шифрования
                else if (type == typeof(Encipherment))
                {
                    // создать алгоритм асимметричного шифрования
                    if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_RSA_PKCS); 
                    
                        // создать алгоритм 
                        Encipherment encipherment = Creator.CreateEncipherment(this, scope, mechanism);   

                        // проверить поддержку алгоритма
                        if (encipherment == null) break; return encipherment; 
                    }
                    if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_oaep)
                    {
                        // раскодировать параметры
                        ASN1.ISO.PKCS.PKCS1.RSAESOAEPParams oaepParameters = 
                            new ASN1.ISO.PKCS.PKCS1.RSAESOAEPParams(parameters);
                
                        // извлечь идентификатор алгоритма хэширования
                        string hashOID = oaepParameters.HashAlgorithm.Algorithm.Value; ulong hashAlg = 0;
        
                        // определить идентификатор алгоритма хэширования
                        if (hashOID == ASN1.ANSI.OID.rsa_md2      ) hashAlg = API.CKM_MD2;       else
                        if (hashOID == ASN1.ANSI.OID.rsa_md5      ) hashAlg = API.CKM_MD5;       else
                        if (hashOID == ASN1.ANSI.OID.tt_ripemd128 ) hashAlg = API.CKM_RIPEMD128; else
                        if (hashOID == ASN1.ANSI.OID.tt_ripemd160 ) hashAlg = API.CKM_RIPEMD160; else
                        if (hashOID == ASN1.ANSI.OID.ssig_sha1    ) hashAlg = API.CKM_SHA_1;     else
                        if (hashOID == ASN1.ANSI.OID.nist_sha2_224) hashAlg = API.CKM_SHA224;    else
                        if (hashOID == ASN1.ANSI.OID.nist_sha2_256) hashAlg = API.CKM_SHA256;    else
                        if (hashOID == ASN1.ANSI.OID.nist_sha2_384) hashAlg = API.CKM_SHA384;    else
                        if (hashOID == ASN1.ANSI.OID.nist_sha2_512) hashAlg = API.CKM_SHA512;    else 
                        if (hashOID == ASN1.ANSI.OID.nist_sha3_224) hashAlg = API.CKM_SHA3_224;  else
                        if (hashOID == ASN1.ANSI.OID.nist_sha3_256) hashAlg = API.CKM_SHA3_256;  else
                        if (hashOID == ASN1.ANSI.OID.nist_sha3_384) hashAlg = API.CKM_SHA3_384;  else
                        if (hashOID == ASN1.ANSI.OID.nist_sha3_512) hashAlg = API.CKM_SHA3_512;  else break; 
        
                        // извлечь идентификатор алгоритма маскирования
                        string maskOID = oaepParameters.MaskGenAlgorithm.Algorithm.Value;
        
                        // проверить поддержку алгоритма
                        if (maskOID != ASN1.ISO.PKCS.PKCS1.OID.rsa_mgf1) break; 
                        
                        // раскодировать параметры маскирования
                        ASN1.ISO.AlgorithmIdentifier maskParameters = new ASN1.ISO.AlgorithmIdentifier(
                            oaepParameters.MaskGenAlgorithm.Parameters
                        );
                        // извлечь идентификатор алгоритма хэширования при маскировании
                        string maskHashOID = maskParameters.Algorithm.Value; ulong mgf = 0; 
        
                        // определить идентификатор алгоритма маскирования
                        if (maskHashOID == ASN1.ANSI.OID.ssig_sha1    ) mgf = API.CKG_MGF1_SHA1;   else
                        if (maskHashOID == ASN1.ANSI.OID.nist_sha2_224) mgf = API.CKG_MGF1_SHA224; else
                        if (maskHashOID == ASN1.ANSI.OID.nist_sha2_256) mgf = API.CKG_MGF1_SHA256; else
                        if (maskHashOID == ASN1.ANSI.OID.nist_sha2_384) mgf = API.CKG_MGF1_SHA384; else
                        if (maskHashOID == ASN1.ANSI.OID.nist_sha2_512) mgf = API.CKG_MGF1_SHA512; else break;    

                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(
                            API.CKM_RSA_PKCS_OAEP, new Parameters.CK_RSA_PKCS_OAEP_PARAMS(
                                hashAlg, mgf, oaepParameters.Label.Value
                        )); 
                        // создать алгоритм 
                        Encipherment encipherment = Creator.CreateEncipherment(this, scope, mechanism);   

                        // проверить поддержку алгоритма
                        if (encipherment == null) break; return encipherment; 
                    }
                }
                // для алгоритмов асимметричного шифрования
                else if (type == typeof(Decipherment))
                {
                    // создать алгоритм асимметричного шифрования
                    if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_RSA_PKCS); 
                    
                        // создать алгоритм 
                        Decipherment decipherment = Creator.CreateDecipherment(this, scope, mechanism);   

                        // проверить поддержку алгоритма
                        if (decipherment == null) break; return decipherment; 
                    }
                    if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_oaep)
                    {
                        // раскодировать параметры
                        ASN1.ISO.PKCS.PKCS1.RSAESOAEPParams oaepParameters = 
                            new ASN1.ISO.PKCS.PKCS1.RSAESOAEPParams(parameters);
                
                        // извлечь идентификатор алгоритма хэширования
                        string hashOID = oaepParameters.HashAlgorithm.Algorithm.Value; ulong hashAlg = 0;
        
                        // определить идентификатор алгоритма хэширования
                        if (hashOID == ASN1.ANSI.OID.rsa_md2      ) hashAlg = API.CKM_MD2;       else
                        if (hashOID == ASN1.ANSI.OID.rsa_md5      ) hashAlg = API.CKM_MD5;       else
                        if (hashOID == ASN1.ANSI.OID.tt_ripemd128 ) hashAlg = API.CKM_RIPEMD128; else
                        if (hashOID == ASN1.ANSI.OID.tt_ripemd160 ) hashAlg = API.CKM_RIPEMD160; else
                        if (hashOID == ASN1.ANSI.OID.ssig_sha1    ) hashAlg = API.CKM_SHA_1;     else
                        if (hashOID == ASN1.ANSI.OID.nist_sha2_224) hashAlg = API.CKM_SHA224;    else
                        if (hashOID == ASN1.ANSI.OID.nist_sha2_256) hashAlg = API.CKM_SHA256;    else
                        if (hashOID == ASN1.ANSI.OID.nist_sha2_384) hashAlg = API.CKM_SHA384;    else
                        if (hashOID == ASN1.ANSI.OID.nist_sha2_512) hashAlg = API.CKM_SHA512;    else 
                        if (hashOID == ASN1.ANSI.OID.nist_sha3_224) hashAlg = API.CKM_SHA3_224;  else
                        if (hashOID == ASN1.ANSI.OID.nist_sha3_256) hashAlg = API.CKM_SHA3_256;  else
                        if (hashOID == ASN1.ANSI.OID.nist_sha3_384) hashAlg = API.CKM_SHA3_384;  else
                        if (hashOID == ASN1.ANSI.OID.nist_sha3_512) hashAlg = API.CKM_SHA3_512;  else break; 
        
                        // извлечь идентификатор алгоритма маскирования
                        string maskOID = oaepParameters.MaskGenAlgorithm.Algorithm.Value;
        
                        // проверить поддержку алгоритма
                        if (maskOID != ASN1.ISO.PKCS.PKCS1.OID.rsa_mgf1) break; 

                        // раскодировать параметры маскирования
                        ASN1.ISO.AlgorithmIdentifier maskParameters = new ASN1.ISO.AlgorithmIdentifier(
                            oaepParameters.MaskGenAlgorithm.Parameters
                        );
                        // извлечь идентификатор алгоритма хэширования при маскировании
                        string maskHashOID = maskParameters.Algorithm.Value; ulong mgf = 0; 
        
                        // определить идентификатор алгоритма маскирования
                        if (maskHashOID == ASN1.ANSI.OID.ssig_sha1    ) mgf = API.CKG_MGF1_SHA1;   else
                        if (maskHashOID == ASN1.ANSI.OID.nist_sha2_224) mgf = API.CKG_MGF1_SHA224; else
                        if (maskHashOID == ASN1.ANSI.OID.nist_sha2_256) mgf = API.CKG_MGF1_SHA256; else
                        if (maskHashOID == ASN1.ANSI.OID.nist_sha2_384) mgf = API.CKG_MGF1_SHA384; else
                        if (maskHashOID == ASN1.ANSI.OID.nist_sha2_512) mgf = API.CKG_MGF1_SHA512; else break;    

                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(
                            API.CKM_RSA_PKCS_OAEP, new Parameters.CK_RSA_PKCS_OAEP_PARAMS(
                                hashAlg, mgf, oaepParameters.Label.Value
                        )); 
                        // создать алгоритм 
                        Decipherment decipherment = Creator.CreateDecipherment(this, scope, mechanism);   

                        // проверить поддержку алгоритма
                        if (decipherment == null) break; return decipherment; 
                    }
                }
                // для алгоритмов подписи
                else if (type == typeof(SignHash))
                {
                    if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_RSA_PKCS); 
                    
                        // создать алгоритм 
                        SignHash signHash = Creator.CreateSignHash(this, scope, mechanism);   

                        // проверить поддержку алгоритма
                        if (signHash == null) break; return signHash; 
                    }
                    if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_pss) 
                    {
                        // раскодировать параметры алгоритма
                        ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams pssParameters = 
                            new ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams(parameters); 
                
                        // проверить вид завершителя
                        if (pssParameters.TrailerField.Value.IntValue != 1) break; 

                        // извлечь идентификатор алгоритма хэширования
                        string hashOID = pssParameters.HashAlgorithm.Algorithm.Value; ulong hashAlg = 0; 
        
                        // определить идентификатор алгоритма хэширования
                        if (hashOID == ASN1.ANSI.OID.rsa_md2      ) hashAlg = API.CKM_MD2;       else
                        if (hashOID == ASN1.ANSI.OID.rsa_md5      ) hashAlg = API.CKM_MD5;       else
                        if (hashOID == ASN1.ANSI.OID.tt_ripemd128 ) hashAlg = API.CKM_RIPEMD128; else
                        if (hashOID == ASN1.ANSI.OID.tt_ripemd160 ) hashAlg = API.CKM_RIPEMD160; else
                        if (hashOID == ASN1.ANSI.OID.ssig_sha1    ) hashAlg = API.CKM_SHA_1;     else
                        if (hashOID == ASN1.ANSI.OID.nist_sha2_224) hashAlg = API.CKM_SHA224;    else
                        if (hashOID == ASN1.ANSI.OID.nist_sha2_256) hashAlg = API.CKM_SHA256;    else
                        if (hashOID == ASN1.ANSI.OID.nist_sha2_384) hashAlg = API.CKM_SHA384;    else
                        if (hashOID == ASN1.ANSI.OID.nist_sha2_512) hashAlg = API.CKM_SHA512;    else 
                        if (hashOID == ASN1.ANSI.OID.nist_sha3_224) hashAlg = API.CKM_SHA3_224;  else
                        if (hashOID == ASN1.ANSI.OID.nist_sha3_256) hashAlg = API.CKM_SHA3_256;  else
                        if (hashOID == ASN1.ANSI.OID.nist_sha3_384) hashAlg = API.CKM_SHA3_384;  else
                        if (hashOID == ASN1.ANSI.OID.nist_sha3_512) hashAlg = API.CKM_SHA3_512;  else break; 
        
                        // извлечь идентификатор алгоритма маскирования
                        string maskOID = pssParameters.MaskGenAlgorithm.Algorithm.Value;
        
                        // проверить поддержку алгоритма
                        if (maskOID != ASN1.ISO.PKCS.PKCS1.OID.rsa_mgf1) break; 
                        
                        // раскодировать параметры маскирования
                        ASN1.ISO.AlgorithmIdentifier maskParameters = new ASN1.ISO.AlgorithmIdentifier(
                            pssParameters.MaskGenAlgorithm.Parameters
                        );
                        // извлечь идентификатор алгоритма хэширования при маскировании
                        string maskHashOID = maskParameters.Algorithm.Value; ulong mgf = 0; 
        
                        // определить идентификатор алгоритма маскирования
                        if (maskHashOID == ASN1.ANSI.OID.ssig_sha1    ) mgf = API.CKG_MGF1_SHA1;   else
                        if (maskHashOID == ASN1.ANSI.OID.nist_sha2_224) mgf = API.CKG_MGF1_SHA224; else
                        if (maskHashOID == ASN1.ANSI.OID.nist_sha2_256) mgf = API.CKG_MGF1_SHA256; else
                        if (maskHashOID == ASN1.ANSI.OID.nist_sha2_384) mgf = API.CKG_MGF1_SHA384; else
                        if (maskHashOID == ASN1.ANSI.OID.nist_sha2_512) mgf = API.CKG_MGF1_SHA512; else break;    

                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(
                            API.CKM_RSA_PKCS_PSS, new Parameters.CK_RSA_PKCS_PSS_PARAMS(
                                hashAlg, mgf, pssParameters.SaltLength.Value.IntValue
                        )); 
                        // создать алгоритм 
                        SignHash signHash = Creator.CreateSignHash(this, scope, mechanism);   

                        // проверить поддержку алгоритма
                        if (signHash == null) break; return signHash; 
                    }
                    if (oid == ASN1.ANSI.OID.x957_dsa) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DSA); 
                    
                        // создать алгоритм 
                        SignHash signHash = Creator.CreateSignHash(this, scope, mechanism);   

                        // проверить поддержку алгоритма
                        if (signHash == null) break; return signHash; 
                    } 
                    if (oid == ASN1.ANSI.OID.x962_ecdsa_sha1) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_ECDSA); 
                    
                        // создать алгоритм 
                        SignHash signHash = Creator.CreateSignHash(this, scope, mechanism);   

                        // проверить поддержку алгоритма
                        if (signHash == null) break; return signHash; 
                    }
                }
                // для алгоритмов подписи
                else if (type == typeof(VerifyHash))
                {
                    if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_RSA_PKCS); 
                    
                        // создать алгоритм 
                        VerifyHash verifyHash = Creator.CreateVerifyHash(this, scope, mechanism);   

                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; return verifyHash; 
                    }
                    if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_pss) 
                    {
                        // раскодировать параметры алгоритма
                        ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams pssParameters = 
                            new ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams(parameters); 
                
                        // проверить вид завершителя
                        if (pssParameters.TrailerField.Value.IntValue != 1) break; 

                        // извлечь идентификатор алгоритма хэширования
                        string hashOID = pssParameters.HashAlgorithm.Algorithm.Value; ulong hashAlg = 0;
        
                        // определить идентификатор алгоритма хэширования
                        if (hashOID == ASN1.ANSI.OID.rsa_md2      ) hashAlg = API.CKM_MD2;       else
                        if (hashOID == ASN1.ANSI.OID.rsa_md5      ) hashAlg = API.CKM_MD5;       else
                        if (hashOID == ASN1.ANSI.OID.tt_ripemd128 ) hashAlg = API.CKM_RIPEMD128; else
                        if (hashOID == ASN1.ANSI.OID.tt_ripemd160 ) hashAlg = API.CKM_RIPEMD160; else
                        if (hashOID == ASN1.ANSI.OID.ssig_sha1    ) hashAlg = API.CKM_SHA_1;     else
                        if (hashOID == ASN1.ANSI.OID.nist_sha2_224) hashAlg = API.CKM_SHA224;    else
                        if (hashOID == ASN1.ANSI.OID.nist_sha2_256) hashAlg = API.CKM_SHA256;    else
                        if (hashOID == ASN1.ANSI.OID.nist_sha2_384) hashAlg = API.CKM_SHA384;    else
                        if (hashOID == ASN1.ANSI.OID.nist_sha2_512) hashAlg = API.CKM_SHA512;    else 
                        if (hashOID == ASN1.ANSI.OID.nist_sha3_224) hashAlg = API.CKM_SHA3_224;  else
                        if (hashOID == ASN1.ANSI.OID.nist_sha3_256) hashAlg = API.CKM_SHA3_256;  else
                        if (hashOID == ASN1.ANSI.OID.nist_sha3_384) hashAlg = API.CKM_SHA3_384;  else
                        if (hashOID == ASN1.ANSI.OID.nist_sha3_512) hashAlg = API.CKM_SHA3_512;  else break; 
        
                        // извлечь идентификатор алгоритма маскирования
                        string maskOID = pssParameters.MaskGenAlgorithm.Algorithm.Value;
        
                        // проверить поддержку алгоритма
                        if (maskOID != ASN1.ISO.PKCS.PKCS1.OID.rsa_mgf1) break; 
                        
                        // раскодировать параметры маскирования
                        ASN1.ISO.AlgorithmIdentifier maskParameters = new ASN1.ISO.AlgorithmIdentifier(
                            pssParameters.MaskGenAlgorithm.Parameters
                        );
                        // извлечь идентификатор алгоритма хэширования при маскировании
                        string maskHashOID = maskParameters.Algorithm.Value; ulong mgf = 0; 
        
                        // определить идентификатор алгоритма маскирования
                        if (maskHashOID == ASN1.ANSI.OID.ssig_sha1    ) mgf = API.CKG_MGF1_SHA1;   else
                        if (maskHashOID == ASN1.ANSI.OID.nist_sha2_224) mgf = API.CKG_MGF1_SHA224; else
                        if (maskHashOID == ASN1.ANSI.OID.nist_sha2_256) mgf = API.CKG_MGF1_SHA256; else
                        if (maskHashOID == ASN1.ANSI.OID.nist_sha2_384) mgf = API.CKG_MGF1_SHA384; else
                        if (maskHashOID == ASN1.ANSI.OID.nist_sha2_512) mgf = API.CKG_MGF1_SHA512; else break;    

                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(
                            API.CKM_RSA_PKCS_PSS, new Parameters.CK_RSA_PKCS_PSS_PARAMS(
                                hashAlg, mgf, pssParameters.SaltLength.Value.IntValue
                        )); 
                        // создать алгоритм 
                        VerifyHash verifyHash = Creator.CreateVerifyHash(this, scope, mechanism);   

                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; return verifyHash; 
                    }
                    if (oid == ASN1.ANSI.OID.x957_dsa) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DSA); 
                    
                        // создать алгоритм 
                        VerifyHash verifyHash = Creator.CreateVerifyHash(this, scope, mechanism);   

                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; return verifyHash; 
                    } 
                    if (oid == ASN1.ANSI.OID.x962_ecdsa_sha1) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_ECDSA); 
                    
                        // создать алгоритм 
                        VerifyHash verifyHash = Creator.CreateVerifyHash(this, scope, mechanism);   

                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; return verifyHash; 
                    }
                }
                // для алгоритмов подписи
                else if (type == typeof(SignData))
                {
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_md2) 
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_MD2_RSA_PKCS); 
                    
                        // создать алгоритм 
                        SignData signData = Creator.CreateSignData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (signData == null) break; return signData; 
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_md5) 
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_MD5_RSA_PKCS); 
                    
                        // создать алгоритм 
                        SignData signData = Creator.CreateSignData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (signData == null) break; return signData; 
			        }
			        if (oid == ASN1.ANSI.OID.tt_rsa_ripemd128) 
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_RIPEMD128_RSA_PKCS); 
                    
                        // создать алгоритм 
                        SignData signData = Creator.CreateSignData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (signData == null) break; return signData; 
			        }
			        if (oid == ASN1.ANSI.OID.tt_rsa_ripemd160) 
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_RIPEMD160_RSA_PKCS); 
                    
                        // создать алгоритм 
                        SignData signData = Creator.CreateSignData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (signData == null) break; return signData; 
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_sha1)
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA1_RSA_PKCS); 
                    
                        // создать алгоритм 
                        SignData signData = Creator.CreateSignData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (signData == null) break; return signData; 
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_sha2_224)
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA224_RSA_PKCS); 
                    
                        // создать алгоритм 
                        SignData signData = Creator.CreateSignData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (signData == null) break; return signData; 
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_sha2_256)
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA256_RSA_PKCS); 
                    
                        // создать алгоритм 
                        SignData signData = Creator.CreateSignData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (signData == null) break; return signData; 
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_sha2_384)
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA384_RSA_PKCS); 
                    
                        // создать алгоритм 
                        SignData signData = Creator.CreateSignData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (signData == null) break; return signData; 
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_sha2_512)
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA512_RSA_PKCS); 
                    
                        // создать алгоритм 
                        SignData signData = Creator.CreateSignData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (signData == null) break; return signData; 
			        }
			        if (oid == ASN1.ANSI.OID.nist_rsa_sha3_224)
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA3_224_RSA_PKCS); 
                    
                        // создать алгоритм 
                        SignData signData = Creator.CreateSignData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (signData == null) break; return signData; 
                    }
			        if (oid == ASN1.ANSI.OID.nist_rsa_sha3_256)
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA3_256_RSA_PKCS); 
                    
                        // создать алгоритм 
                        SignData signData = Creator.CreateSignData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (signData == null) break; return signData; 
                    }
			        if (oid == ASN1.ANSI.OID.nist_rsa_sha3_384)
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA3_384_RSA_PKCS); 
                    
                        // создать алгоритм 
                        SignData signData = Creator.CreateSignData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (signData == null) break; return signData; 
                    }
			        if (oid == ASN1.ANSI.OID.nist_rsa_sha3_512)
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA3_512_RSA_PKCS); 
                    
                        // создать алгоритм 
                        SignData signData = Creator.CreateSignData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (signData == null) break; return signData; 
                    }
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_pss) 
			        {
                        // раскодировать параметры алгоритма
                        ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams pssParameters = 
                            new ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams(parameters); 
                
                        // проверить вид завершителя
                        if (pssParameters.TrailerField.Value.IntValue != 1) break; ulong algID = 0; 

                        // извлечь идентификатор алгоритма хэширования
                        string hashOID = pssParameters.HashAlgorithm.Algorithm.Value; ulong hashAlg = 0;

                        if (hashOID == ASN1.ANSI.OID.ssig_sha1) 
                        {
                            // указать идентификаторы алгоритмов
                            algID = API.CKM_SHA1_RSA_PKCS_PSS; hashAlg = API.CKM_SHA_1;  
                        }
                        else if (hashOID == ASN1.ANSI.OID.nist_sha2_224) 
                        {
                            // указать идентификаторы алгоритмов
                            algID = API.CKM_SHA224_RSA_PKCS_PSS; hashAlg = API.CKM_SHA224;    
                        }
                        else if (hashOID == ASN1.ANSI.OID.nist_sha2_256) 
                        {
                            // указать идентификаторы алгоритмов
                            algID = API.CKM_SHA256_RSA_PKCS_PSS; hashAlg = API.CKM_SHA256;    
                        }
                        else if (hashOID == ASN1.ANSI.OID.nist_sha2_384) 
                        {
                            // указать идентификаторы алгоритмов
                            algID = API.CKM_SHA384_RSA_PKCS_PSS; hashAlg = API.CKM_SHA384;    
                        }
                        else if (hashOID == ASN1.ANSI.OID.nist_sha2_512) 
                        {
                            // указать идентификаторы алгоритмов
                            algID = API.CKM_SHA512_RSA_PKCS_PSS; hashAlg = API.CKM_SHA512;    
                        }
                        else if (hashOID == ASN1.ANSI.OID.nist_sha3_224) 
                        {
                            // указать идентификаторы алгоритмов
                            algID = API.CKM_SHA3_224_RSA_PKCS_PSS; hashAlg = API.CKM_SHA3_224;    
                        }
                        else if (hashOID == ASN1.ANSI.OID.nist_sha3_256) 
                        {
                            // указать идентификаторы алгоритмов
                            algID = API.CKM_SHA3_256_RSA_PKCS_PSS; hashAlg = API.CKM_SHA3_256;    
                        }
                        else if (hashOID == ASN1.ANSI.OID.nist_sha3_384) 
                        {
                            // указать идентификаторы алгоритмов
                            algID = API.CKM_SHA3_384_RSA_PKCS_PSS; hashAlg = API.CKM_SHA3_384;    
                        }
                        else if (hashOID == ASN1.ANSI.OID.nist_sha3_512) 
                        {
                            // указать идентификаторы алгоритмов
                            algID = API.CKM_SHA3_512_RSA_PKCS_PSS; hashAlg = API.CKM_SHA3_512;    
                        }
                        // извлечь идентификатор алгоритма маскирования
                        else break; string maskOID = pssParameters.MaskGenAlgorithm.Algorithm.Value;

                        // проверить поддержку алгоритма
                        if (maskOID != ASN1.ISO.PKCS.PKCS1.OID.rsa_mgf1) break; 
                        
                        // раскодировать параметры маскирования
                        ASN1.ISO.AlgorithmIdentifier maskParameters = new ASN1.ISO.AlgorithmIdentifier(
                             pssParameters.MaskGenAlgorithm.Parameters
                        );
                        // извлечь идентификатор алгоритма хэширования при маскировании
                        string maskHashOID = maskParameters.Algorithm.Value; ulong mgf = 0; 

                        // определить идентификатор алгоритма маскирования
                        if (maskHashOID == ASN1.ANSI.OID.ssig_sha1    ) mgf = API.CKG_MGF1_SHA1;   else
                        if (maskHashOID == ASN1.ANSI.OID.nist_sha2_224) mgf = API.CKG_MGF1_SHA224; else
                        if (maskHashOID == ASN1.ANSI.OID.nist_sha2_256) mgf = API.CKG_MGF1_SHA256; else
                        if (maskHashOID == ASN1.ANSI.OID.nist_sha2_384) mgf = API.CKG_MGF1_SHA384; else
                        if (maskHashOID == ASN1.ANSI.OID.nist_sha2_512) mgf = API.CKG_MGF1_SHA512; else break;    
                        
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(algID, 
                            new Parameters.CK_RSA_PKCS_PSS_PARAMS(
                                hashAlg, mgf, pssParameters.SaltLength.Value.IntValue
                        )); 
                        // создать алгоритм 
                        SignData signData = Creator.CreateSignData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (signData == null) break; return signData; 
			        }
   			        if (oid == ASN1.ANSI.OID.x957_dsa_sha1) 
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DSA_SHA1); 
                    
                        // создать алгоритм 
                        SignData signData = Creator.CreateSignData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (signData == null) break; return signData; 
                    }
   			        if (oid == ASN1.ANSI.OID.nist_dsa_sha2_224) 
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DSA_SHA224); 
                    
                        // создать алгоритм 
                        SignData signData = Creator.CreateSignData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (signData == null) break; return signData; 
                    }
   			        if (oid == ASN1.ANSI.OID.nist_dsa_sha2_256) 
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DSA_SHA256); 
                    
                        // создать алгоритм 
                        SignData signData = Creator.CreateSignData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (signData == null) break; return signData; 
                    }
   			        if (oid == ASN1.ANSI.OID.nist_dsa_sha2_384) 
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DSA_SHA384); 
                    
                        // создать алгоритм 
                        SignData signData = Creator.CreateSignData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (signData == null) break; return signData; 
                    }
   			        if (oid == ASN1.ANSI.OID.nist_dsa_sha2_512) 
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DSA_SHA512); 
                    
                        // создать алгоритм 
                        SignData signData = Creator.CreateSignData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (signData == null) break; return signData; 
                    }
                    if (oid == ASN1.ANSI.OID.x962_ecdsa_sha1)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_ECDSA_SHA1); 
                    
                        // создать алгоритм 
                        SignData signData = Creator.CreateSignData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (signData == null) break; return signData; 
                    }
                    if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2_224)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_ECDSA_SHA224); 
                    
                        // создать алгоритм 
                        SignData signData = Creator.CreateSignData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (signData == null) break; return signData; 
                    }
                    if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2_256)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_ECDSA_SHA256); 
                    
                        // создать алгоритм 
                        SignData signData = Creator.CreateSignData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (signData == null) break; return signData; 
                    }
                    if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2_384)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_ECDSA_SHA384); 
                    
                        // создать алгоритм 
                        SignData signData = Creator.CreateSignData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (signData == null) break; return signData; 
                    }
                    if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2_512)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_ECDSA_SHA512); 
                    
                        // создать алгоритм 
                        SignData signData = Creator.CreateSignData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (signData == null) break; return signData; 
                    }
                }
                // для алгоритмов проверки подписи
                else if (type == typeof(VerifyData))
                {
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_md2) 
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_MD2_RSA_PKCS); 
                    
                        // создать алгоритм 
                        VerifyData verifyData = Creator.CreateVerifyData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (verifyData == null) break; return verifyData; 
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_md5) 
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_MD5_RSA_PKCS); 
                    
                        // создать алгоритм 
                        VerifyData verifyData = Creator.CreateVerifyData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (verifyData == null) break; return verifyData; 
			        }
			        if (oid == ASN1.ANSI.OID.tt_rsa_ripemd128) 
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_RIPEMD128_RSA_PKCS); 
                    
                        // создать алгоритм 
                        VerifyData verifyData = Creator.CreateVerifyData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (verifyData == null) break; return verifyData; 
			        }
			        if (oid == ASN1.ANSI.OID.tt_rsa_ripemd160) 
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_RIPEMD160_RSA_PKCS); 
                    
                        // создать алгоритм 
                        VerifyData verifyData = Creator.CreateVerifyData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (verifyData == null) break; return verifyData; 
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_sha1)
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA1_RSA_PKCS);
                    
                        // создать алгоритм 
                        VerifyData verifyData = Creator.CreateVerifyData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (verifyData == null) break; return verifyData; 
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_sha2_224)
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA224_RSA_PKCS); 
                    
                        // создать алгоритм 
                        VerifyData verifyData = Creator.CreateVerifyData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (verifyData == null) break; return verifyData; 
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_sha2_256)
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA256_RSA_PKCS); 
                    
                        // создать алгоритм 
                        VerifyData verifyData = Creator.CreateVerifyData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (verifyData == null) break; return verifyData; 
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_sha2_384)
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA384_RSA_PKCS); 
                    
                        // создать алгоритм 
                        VerifyData verifyData = Creator.CreateVerifyData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (verifyData == null) break; return verifyData; 
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_sha2_512)
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA512_RSA_PKCS); 
                    
                        // создать алгоритм 
                        VerifyData verifyData = Creator.CreateVerifyData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (verifyData == null) break; return verifyData; 
			        }
			        if (oid == ASN1.ANSI.OID.nist_rsa_sha3_224)
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA3_224_RSA_PKCS); 
                    
                        // создать алгоритм 
                        VerifyData verifyData = Creator.CreateVerifyData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (verifyData == null) break; return verifyData; 
                    }
			        if (oid == ASN1.ANSI.OID.nist_rsa_sha3_256)
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA3_256_RSA_PKCS); 
                    
                        // создать алгоритм 
                        VerifyData verifyData = Creator.CreateVerifyData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (verifyData == null) break; return verifyData; 
                    }
			        if (oid == ASN1.ANSI.OID.nist_rsa_sha3_384)
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA3_384_RSA_PKCS); 
                    
                        // создать алгоритм 
                        VerifyData verifyData = Creator.CreateVerifyData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (verifyData == null) break; return verifyData; 
                    }
			        if (oid == ASN1.ANSI.OID.nist_rsa_sha3_512)
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_SHA3_512_RSA_PKCS); 
                    
                        // создать алгоритм 
                        VerifyData verifyData = Creator.CreateVerifyData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (verifyData == null) break; return verifyData; 
                    }
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_pss) 
			        {
                        // раскодировать параметры алгоритма
                        ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams pssParameters = 
                            new ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams(parameters); 
                
                        // проверить вид завершителя
                        if (pssParameters.TrailerField.Value.IntValue != 1) break; ulong algID = 0; 

                        // извлечь идентификатор алгоритма хэширования
                        string hashOID = pssParameters.HashAlgorithm.Algorithm.Value; ulong hashAlg = 0;

                        if (hashOID == ASN1.ANSI.OID.ssig_sha1) 
                        {
                            // указать идентификаторы алгоритмов
                            algID = API.CKM_SHA1_RSA_PKCS_PSS; hashAlg = API.CKM_SHA_1;  
                        }
                        else if (hashOID == ASN1.ANSI.OID.nist_sha2_224) 
                        {
                            // указать идентификаторы алгоритмов
                            algID = API.CKM_SHA224_RSA_PKCS_PSS; hashAlg = API.CKM_SHA224;    
                        }
                        else if (hashOID == ASN1.ANSI.OID.nist_sha2_256) 
                        {
                            // указать идентификаторы алгоритмов
                            algID = API.CKM_SHA256_RSA_PKCS_PSS; hashAlg = API.CKM_SHA256;    
                        }
                        else if (hashOID == ASN1.ANSI.OID.nist_sha2_384) 
                        {
                            // указать идентификаторы алгоритмов
                            algID = API.CKM_SHA384_RSA_PKCS_PSS; hashAlg = API.CKM_SHA384;    
                        }
                        else if (hashOID == ASN1.ANSI.OID.nist_sha2_512) 
                        {
                            // указать идентификаторы алгоритмов
                            algID = API.CKM_SHA512_RSA_PKCS_PSS; hashAlg = API.CKM_SHA512;    
                        }
                        else if (hashOID == ASN1.ANSI.OID.nist_sha3_224) 
                        {
                            // указать идентификаторы алгоритмов
                            algID = API.CKM_SHA3_224_RSA_PKCS_PSS; hashAlg = API.CKM_SHA3_224;    
                        }
                        else if (hashOID == ASN1.ANSI.OID.nist_sha3_256) 
                        {
                            // указать идентификаторы алгоритмов
                            algID = API.CKM_SHA3_256_RSA_PKCS_PSS; hashAlg = API.CKM_SHA3_256;    
                        }
                        else if (hashOID == ASN1.ANSI.OID.nist_sha3_384) 
                        {
                            // указать идентификаторы алгоритмов
                            algID = API.CKM_SHA3_384_RSA_PKCS_PSS; hashAlg = API.CKM_SHA3_384;    
                        }
                        else if (hashOID == ASN1.ANSI.OID.nist_sha3_512) 
                        {
                            // указать идентификаторы алгоритмов
                            algID = API.CKM_SHA3_512_RSA_PKCS_PSS; hashAlg = API.CKM_SHA3_512;    
                        }
                        // извлечь идентификатор алгоритма маскирования
                        else break; string maskOID = pssParameters.MaskGenAlgorithm.Algorithm.Value;

                        // проверить поддержку алгоритма
                        if (maskOID != ASN1.ISO.PKCS.PKCS1.OID.rsa_mgf1) break; 
                        
                        // раскодировать параметры маскирования
                        ASN1.ISO.AlgorithmIdentifier maskParameters = new ASN1.ISO.AlgorithmIdentifier(
                            pssParameters.MaskGenAlgorithm.Parameters
                        );
                        // извлечь идентификатор алгоритма хэширования при маскировании
                        string maskHashOID = maskParameters.Algorithm.Value; ulong mgf = 0; 

                        // определить идентификатор алгоритма маскирования
                        if (maskHashOID == ASN1.ANSI.OID.ssig_sha1    ) mgf = API.CKG_MGF1_SHA1;   else
                        if (maskHashOID == ASN1.ANSI.OID.nist_sha2_224) mgf = API.CKG_MGF1_SHA224; else
                        if (maskHashOID == ASN1.ANSI.OID.nist_sha2_256) mgf = API.CKG_MGF1_SHA256; else
                        if (maskHashOID == ASN1.ANSI.OID.nist_sha2_384) mgf = API.CKG_MGF1_SHA384; else
                        if (maskHashOID == ASN1.ANSI.OID.nist_sha2_512) mgf = API.CKG_MGF1_SHA512; else break;    

                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(algID, 
                            new Parameters.CK_RSA_PKCS_PSS_PARAMS(
                                hashAlg, mgf, pssParameters.SaltLength.Value.IntValue
                        )); 
                        // создать алгоритм 
                        VerifyData verifyData = Creator.CreateVerifyData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (verifyData == null) break; return verifyData; 
			        }
   			        if (oid == ASN1.ANSI.OID.x957_dsa_sha1) 
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DSA_SHA1); 
                    
                        // создать алгоритм 
                        VerifyData verifyData = Creator.CreateVerifyData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (verifyData == null) break; return verifyData; 
                    }
   			        if (oid == ASN1.ANSI.OID.nist_dsa_sha2_224) 
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DSA_SHA224); 
                    
                        // создать алгоритм 
                        VerifyData verifyData = Creator.CreateVerifyData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (verifyData == null) break; return verifyData; 
                    }
   			        if (oid == ASN1.ANSI.OID.nist_dsa_sha2_256) 
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DSA_SHA256); 
                    
                        // создать алгоритм 
                        VerifyData verifyData = Creator.CreateVerifyData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (verifyData == null) break; return verifyData; 
                    }
   			        if (oid == ASN1.ANSI.OID.nist_dsa_sha2_384) 
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DSA_SHA384); 
                    
                        // создать алгоритм 
                        VerifyData verifyData = Creator.CreateVerifyData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (verifyData == null) break; return verifyData; 
                    }
   			        if (oid == ASN1.ANSI.OID.nist_dsa_sha2_512) 
			        {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DSA_SHA512); 
                    
                        // создать алгоритм 
                        VerifyData verifyData = Creator.CreateVerifyData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (verifyData == null) break; return verifyData; 
                    }
                    if (oid == ASN1.ANSI.OID.x962_ecdsa_sha1)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_ECDSA_SHA1); 
                    
                        // создать алгоритм 
                        VerifyData verifyData = Creator.CreateVerifyData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (verifyData == null) break; return verifyData; 
                    }
                    if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2_224)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_ECDSA_SHA224); 
                    
                        // создать алгоритм 
                        VerifyData verifyData = Creator.CreateVerifyData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (verifyData == null) break; return verifyData; 
                    }
                    if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2_256)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_ECDSA_SHA256); 
                    
                        // создать алгоритм 
                        VerifyData verifyData = Creator.CreateVerifyData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (verifyData == null) break; return verifyData; 
                    }
                    if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2_384)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_ECDSA_SHA384); 
                    
                        // создать алгоритм 
                        VerifyData verifyData = Creator.CreateVerifyData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (verifyData == null) break; return verifyData; 
                    }
                    if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2_512)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_ECDSA_SHA512); 
                    
                        // создать алгоритм 
                        VerifyData verifyData = Creator.CreateVerifyData(this, scope, mechanism);

                        // проверить поддержку алгоритма
                        if (verifyData == null) break; return verifyData; 
                    }
                }
                // для алгоритмов согласования общего ключа
                else if (type == typeof(IKeyAgreement))
                {
                    if (oid == ASN1.ANSI.OID.x942_dh_public_key)
                    {
                        // указать идентификатор алгоритма
                        ulong algID = API.CKM_X9_42_DH_DERIVE; ulong kdf = API.CKD_NULL; 
                    
                        // создать алгоритм согласования ключа
                        KeyAgreement keyAgreement = Creator.CreateKeyAgreement(
                            this, scope, algID, kdf, null
                        ); 
                        // проверить поддержку алгоритма
                        if (keyAgreement == null) break; return keyAgreement; 
                    }
                    if (oid == ASN1.ANSI.OID.x962_ec_public_key)
                    {
                        // указать идентификатор алгоритма
                        ulong algID = API.CKM_ECDH1_DERIVE; ulong kdf = API.CKD_NULL; 
                    
                        // создать алгоритм согласования ключа
                        KeyAgreement keyAgreement = Creator.CreateKeyAgreement(
                            this, scope, algID, kdf, null
                        ); 
                        // проверить поддержку алгоритма
                        if (keyAgreement == null) break; return keyAgreement; 
                    }
                    if (oid == ASN1.ISO.PKCS.PKCS9.OID.smime_ssdh || 
                        oid == ASN1.ISO.PKCS.PKCS9.OID.smime_esdh)
                    {
                        // раскодировать параметры
                        ASN1.ISO.AlgorithmIdentifier wrapParameters = 
                            new ASN1.ISO.AlgorithmIdentifier(parameters); 

                        // указать идентификатор алгоритма
                        ulong algID = API.CKM_X9_42_DH_DERIVE; ulong kdf = API.CKD_SHA1_KDF_ASN1; 
                    
                        // получить алгоритм согласования общего ключа
                        return Creator.CreateKeyAgreement(
                            this, scope, algID, kdf, wrapParameters
                        ); 
                    }
                    if (oid == ASN1.ANSI.OID.x963_ecdh_std_sha1)
                    {
                        // раскодировать параметры
                        ASN1.ISO.AlgorithmIdentifier wrapParameters = 
                            new ASN1.ISO.AlgorithmIdentifier(parameters); 

                        // указать идентификатор алгоритма
                        ulong algID = API.CKM_ECDH1_DERIVE; ulong kdf = API.CKD_SHA1_KDF; 
                    
                        // получить алгоритм согласования общего ключа
                        return Creator.CreateKeyAgreement(
                            this, scope, algID, kdf, wrapParameters
                        ); 
                    }
                    if (oid == ASN1.ANSI.OID.certicom_ecdh_std_sha2_224)
                    {
                        // раскодировать параметры
                        ASN1.ISO.AlgorithmIdentifier wrapParameters = 
                            new ASN1.ISO.AlgorithmIdentifier(parameters); 

                        // указать идентификатор алгоритма
                        ulong algID = API.CKM_ECDH1_DERIVE; ulong kdf = API.CKD_SHA224_KDF; 
                    
                        // получить алгоритм согласования общего ключа
                        return Creator.CreateKeyAgreement(
                            this, scope, algID, kdf, wrapParameters
                        ); 
                    }
                    if (oid == ASN1.ANSI.OID.certicom_ecdh_std_sha2_256)
                    {
                        // раскодировать параметры
                        ASN1.ISO.AlgorithmIdentifier wrapParameters = 
                            new ASN1.ISO.AlgorithmIdentifier(parameters); 

                        // указать идентификатор алгоритма
                        ulong algID = API.CKM_ECDH1_DERIVE; ulong kdf = API.CKD_SHA256_KDF; 
                    
                        // получить алгоритм согласования общего ключа
                        return Creator.CreateKeyAgreement(
                            this, scope, algID, kdf, wrapParameters
                        ); 
                    }
                    if (oid == ASN1.ANSI.OID.certicom_ecdh_std_sha2_384)
                    {
                        // раскодировать параметры
                        ASN1.ISO.AlgorithmIdentifier wrapParameters = 
                            new ASN1.ISO.AlgorithmIdentifier(parameters); 

                        // указать идентификатор алгоритма
                        ulong algID = API.CKM_ECDH1_DERIVE; ulong kdf = API.CKD_SHA384_KDF; 
                    
                        // получить алгоритм согласования общего ключа
                        return Creator.CreateKeyAgreement(
                            this, scope, algID, kdf, wrapParameters
                        ); 
                    }
                    if (oid == ASN1.ANSI.OID.certicom_ecdh_std_sha2_512)
                    {
                        // раскодировать параметры
                        ASN1.ISO.AlgorithmIdentifier wrapParameters = 
                            new ASN1.ISO.AlgorithmIdentifier(parameters); 

                        // указать идентификатор алгоритма
                        ulong algID = API.CKM_ECDH1_DERIVE; ulong kdf = API.CKD_SHA512_KDF; 
                    
                        // получить алгоритм согласования общего ключа
                        return Creator.CreateKeyAgreement(
                            this, scope, algID, kdf, wrapParameters
                        ); 
                    }
                    if (oid == ASN1.ANSI.OID.x963_ecdh_cofactor_sha1)
                    {
                        // раскодировать параметры
                        ASN1.ISO.AlgorithmIdentifier wrapParameters = 
                            new ASN1.ISO.AlgorithmIdentifier(parameters); 

                        // указать идентификатор алгоритма
                        ulong algID = API.CKM_ECDH1_COFACTOR_DERIVE; ulong kdf = API.CKD_SHA1_KDF; 
                    
                        // получить алгоритм согласования общего ключа
                        return Creator.CreateKeyAgreement(
                            this, scope, algID, kdf, wrapParameters
                        ); 
                    }
                    if (oid == ASN1.ANSI.OID.certicom_ecdh_cofactor_sha2_224)
                    {
                        // раскодировать параметры
                        ASN1.ISO.AlgorithmIdentifier wrapParameters = 
                            new ASN1.ISO.AlgorithmIdentifier(parameters); 

                        // указать идентификатор алгоритма
                        ulong algID = API.CKM_ECDH1_COFACTOR_DERIVE; ulong kdf = API.CKD_SHA224_KDF; 
                    
                        // получить алгоритм согласования общего ключа
                        return Creator.CreateKeyAgreement(
                            this, scope, algID, kdf, wrapParameters
                        ); 
                    }
                    if (oid == ASN1.ANSI.OID.certicom_ecdh_cofactor_sha2_256)
                    {
                        // раскодировать параметры
                        ASN1.ISO.AlgorithmIdentifier wrapParameters = 
                            new ASN1.ISO.AlgorithmIdentifier(parameters); 

                        // указать идентификатор алгоритма
                        ulong algID = API.CKM_ECDH1_COFACTOR_DERIVE; ulong kdf = API.CKD_SHA256_KDF; 
                    
                        // получить алгоритм согласования общего ключа
                        return Creator.CreateKeyAgreement(
                            this, scope, algID, kdf, wrapParameters
                        ); 
                    }
                    if (oid == ASN1.ANSI.OID.certicom_ecdh_cofactor_sha2_384)
                    {
                        // раскодировать параметры
                        ASN1.ISO.AlgorithmIdentifier wrapParameters = 
                            new ASN1.ISO.AlgorithmIdentifier(parameters); 

                        // указать идентификатор алгоритма
                        ulong algID = API.CKM_ECDH1_COFACTOR_DERIVE; ulong kdf = API.CKD_SHA384_KDF; 
                    
                        // получить алгоритм согласования общего ключа
                        return Creator.CreateKeyAgreement(
                            this, scope, algID, kdf, wrapParameters
                        ); 
                    }
                    if (oid == ASN1.ANSI.OID.certicom_ecdh_cofactor_sha2_512)
                    {
                        // раскодировать параметры
                        ASN1.ISO.AlgorithmIdentifier wrapParameters = 
                            new ASN1.ISO.AlgorithmIdentifier(parameters); 

                        // указать идентификатор алгоритма
                        ulong algID = API.CKM_ECDH1_COFACTOR_DERIVE; ulong kdf = API.CKD_SHA512_KDF; 
                    
                        // получить алгоритм согласования общего ключа
                        return Creator.CreateKeyAgreement(
                            this, scope, algID, kdf, wrapParameters
                        ); 
                    }
                }
            }
            // вызвать базовую функцию
            return ANSI.Factory.RedirectAlgorithm(factory, scope, oid, parameters, type); 
        }
    }
}
