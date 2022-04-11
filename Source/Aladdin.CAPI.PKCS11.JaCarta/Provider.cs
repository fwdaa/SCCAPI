﻿using System;
using System.Security;
using System.Security.Permissions;
using System.Collections.Generic;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11.JaCarta
{
	///////////////////////////////////////////////////////////////////////////
	// Криптографический провайдер
	///////////////////////////////////////////////////////////////////////////
	public sealed class Provider : CAPI.ANSI.PKCS11.Provider
	{
        // интерфейс вызова функций и криптографические провайдер
        private Module module; private GOST.PKCS11.Provider gostProvider;

		// конструктор
		public Provider() : base("JaCarta PKCS11 Cryptographic Provider", true) 
        {
            // указать интерфейс вызова функций
            module = Aladdin.PKCS11.Module.Create(new NativeMethods.NativeAPI()); 

            // создать криптографические провайдеры
            gostProvider = new GOST.PKCS11.Provider(module, Name, false); 
        }
        // деструктор
        protected override void OnDispose() 
        {
            // освободить выделенные ресурсы
            gostProvider.Dispose(); RefObject.Release(module); base.OnDispose(); 
        } 
		// интерфейс вызова функций
		public override Module Module { get { return module; }} 

        ///////////////////////////////////////////////////////////////////////
        // Поддерживаемые ключи
        ///////////////////////////////////////////////////////////////////////
	    public override Dictionary<String, SecretKeyFactory> SecretKeyFactories() 
        { 
            // создать список поддерживаемых ключей
            Dictionary<String, SecretKeyFactory> keyFactories = 
                new Dictionary<String, SecretKeyFactory>(); 
        
            // для всех поддерживаемых ключей
            foreach (KeyValuePair<String, SecretKeyFactory> entry in gostProvider.SecretKeyFactories())
            {
                // проверить отсутствие элемента
                if (keyFactories.ContainsKey(entry.Key)) continue; 

                // добавить фабрику в таблицу
                keyFactories.Add(entry.Key, entry.Value); 
            }
            // для всех поддерживаемых ключей
            foreach (KeyValuePair<String, SecretKeyFactory> entry in base.SecretKeyFactories())
            {
                // проверить отсутствие элемента
                if (keyFactories.ContainsKey(entry.Key)) continue; 

                // добавить фабрику в таблицу
                keyFactories.Add(entry.Key, entry.Value); 
            }
            return keyFactories; 
        }
	    public override Dictionary<String, KeyFactory> KeyFactories() 
        { 
            // создать список поддерживаемых ключей
            Dictionary<String, KeyFactory> keyFactories = new Dictionary<String, KeyFactory>(); 
        
            // для всех поддерживаемых ключей
            foreach (KeyValuePair<String, KeyFactory> entry in gostProvider.KeyFactories())
            {
                // проверить отсутствие элемента
                if (keyFactories.ContainsKey(entry.Key)) continue; 

                // добавить фабрику в таблицу
                keyFactories.Add(entry.Key, entry.Value); 
            }
            // для всех поддерживаемых ключей
            foreach (KeyValuePair<String, KeyFactory> entry in base.KeyFactories())
            {
                // проверить отсутствие элемента
                if (keyFactories.ContainsKey(entry.Key)) continue; 

                // добавить фабрику в таблицу
                keyFactories.Add(entry.Key, entry.Value); 
            }
            return keyFactories; 
        }
	    public override string[] GeneratedKeys(SecurityStore scope) 
	    {
            // создать список генерируемых ключей
            List<String> keyOIDs = new List<String>(); 
        
            // заполнить список генерируемых ключей
            keyOIDs.AddRange(gostProvider.GeneratedKeys(scope)); 

            // вызвать базовую функцию
            keyOIDs.AddRange(base.GeneratedKeys(scope)); 

            // вернуть список ключей
            return keyOIDs.ToArray(); 
	    }
	    // преобразование ключей
	    public override IPublicKey ConvertPublicKey(
            CAPI.PKCS11.Applet applet, SessionObject obj)
        {
            // выполнить преобразование ключа
            IPublicKey publicKey = gostProvider.ConvertPublicKey(applet, obj); 
        
            // проверить наличие преобразования
            if (publicKey != null) return publicKey; 
            
            // вызвать базовую функцию
            return base.ConvertPublicKey(applet, obj); 
        }
	    public override CAPI.PKCS11.PrivateKey ConvertPrivateKey(
            SecurityObject scope, SessionObject obj, IPublicKey publicKey)
        {
            // выполнить преобразование ключа
            CAPI.PKCS11.PrivateKey privateKey = 
                gostProvider.ConvertPrivateKey(scope, obj, publicKey); 
        
            // проверить наличие преобразования
            if (privateKey != null) return privateKey; 
            
            // вызвать базовую функцию
            return base.ConvertPrivateKey(scope, obj, publicKey); 
        }
	    // атрибуты открытого и личного ключа
        public override CAPI.PKCS11.Attribute[] PublicKeyAttributes(
            CAPI.PKCS11.Applet applet, IPublicKey publicKey, MechanismInfo info) 
        {
            // получить атрибуты открытого ключа
            CAPI.PKCS11.Attribute[] attributes = 
                gostProvider.PublicKeyAttributes(applet, publicKey, info); 
        
            // проверить наличие атрибутов
            if (attributes != null) return attributes; 
            
            // вызвать базовую функцию
            return base.PublicKeyAttributes(applet, publicKey, info); 
        }
        public override CAPI.PKCS11.Attribute[] PrivateKeyAttributes(
            CAPI.PKCS11.Applet applet, IPrivateKey privateKey, MechanismInfo info)
        {
            // получить атрибуты личного ключа
            CAPI.PKCS11.Attribute[] attributes = 
                gostProvider.PrivateKeyAttributes(applet, privateKey, info); 
        
            // проверить наличие атрибутов
            if (attributes != null) return attributes; 
            
            // вызвать базовую функцию
            return base.PrivateKeyAttributes(applet, privateKey, info); 
        }
	    // атрибуты симметричного ключа
	    public override CAPI.PKCS11.Attribute[] SecretKeyAttributes(
            SecretKeyFactory keyFactory, int keySize, bool hasValue) 
        { 
            // получить атрибуты симметричного ключа 
            CAPI.PKCS11.Attribute[] attributes = gostProvider.SecretKeyAttributes(
                keyFactory, keySize, hasValue
            ); 
            // проверить наличие атрибутов
            if (attributes[0].GetLong(Module) != API.CKK_GENERIC_SECRET) return attributes; 
            
            // вызвать базовую функцию
            return base.SecretKeyAttributes(keyFactory, keySize, hasValue); 
        }
	    // создать алгоритм генерации ключей
	    protected override CAPI.KeyPairGenerator CreateGenerator(
            CAPI.Factory factory, SecurityObject scope, 
            IRand rand, string keyOID, IParameters parameters) 
        {
            // создать алгоритм генерации ключей
            CAPI.KeyPairGenerator generator = gostProvider.CreateGenerator(
                scope, rand, keyOID, parameters
            ); 
            // проверить наличие генератора
            if (generator != null) return generator; 

            // вызвать базовую функцию
            return base.CreateGenerator(factory, scope, rand, keyOID, parameters); 
        }
	    // создать алгоритм для параметров
	    protected override IAlgorithm CreateAlgorithm(
            CAPI.Factory factory, SecurityStore scope, 
		    String oid, ASN1.IEncodable parameters, Type type)
        {
            // для алгоритмов ассиметричного шифрования
            if (type == typeof(CAPI.Encipherment))
            {
                // указать неподдерживаемые алгоритмы
                if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_oaep) return null; 
            }
            // для алгоритмов ассиметричного шифрования
            else if (type == typeof(CAPI.Decipherment))
            {
                // указать неподдерживаемые алгоритмы
                if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_oaep) return null; 
            }
            // для алгоритмов проверки подписи хэш-значения
            else if (type == typeof(CAPI.VerifyHash))
            {
                // указать неподдерживаемые алгоритмы
                if (oid == ASN1.ANSI.OID.x962_ecdsa_sha1) return null; 
            }
            // для алгоритмов проверки подписи данных
            else if (type == typeof(CAPI.VerifyData))
            {
                // указать неподдерживаемые алгоритмы
                if (oid == ASN1.ANSI.OID.x962_ecdsa_sha1    ) return null; 
                if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2_224) return null; 
                if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2_256) return null; 
                if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2_384) return null; 
                if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2_512) return null; 
            }
            // создать алгоритм
            IAlgorithm algorithm = gostProvider.CreateAlgorithm(scope, oid, parameters, type); 

            // проверить наличие алгоритма
            if (algorithm != null) return algorithm; 
        
            // вызвать базовую функцию
            return base.CreateAlgorithm(factory, scope, oid, parameters, type); 
        }
    }
}
