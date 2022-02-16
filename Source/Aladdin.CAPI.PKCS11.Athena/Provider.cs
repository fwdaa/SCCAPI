using System;
using System.Security;
using System.Security.Permissions;
using System.Collections.Generic;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11.Athena
{
	///////////////////////////////////////////////////////////////////////////
	// Криптографический провайдер
	///////////////////////////////////////////////////////////////////////////
	public sealed class Provider : ANSI.PKCS11.Provider
	{
		// конструктор
		public Provider() : base("Athena PKCS11 Cryptographic Provider", false) 
        {
            // указать интерфейс вызова функций
            module = Aladdin.PKCS11.Module.Create(new NativeMethods.NativeAPI()); 
        }
        // деструктор
        protected override void OnDispose() 
        {
            // освободить выделенные ресурсы
            RefObject.Release(module); base.OnDispose(); 
        } 
		// интерфейс вызова функций
		public override Module Module { get { return module; }} private Module module;

        // корректная реализация OAEP/PSS механизмов
        public override bool UseOAEP(CAPI.PKCS11.Applet applet) { return true;  } 
        public override bool UsePSS (CAPI.PKCS11.Applet applet) { return false; } 

	    // создать алгоритм генерации ключей
	    protected override CAPI.KeyPairGenerator CreateGenerator(
            CAPI.Factory factory, SecurityObject scope, 
            IRand rand, string keyOID, IParameters parameters) 
        {
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
            // вызвать базовую функцию
            return base.CreateGenerator(factory, scope, rand, keyOID, parameters); 
        }
	    // создать алгоритм для параметров
	    protected override IAlgorithm CreateAlgorithm(CAPI.Factory factory, 
            SecurityStore scope, ASN1.ISO.AlgorithmIdentifier parameters, Type type)
        {
            // определить идентификатор алгоритма
		    string oid = parameters.Algorithm.Value; 

            // для алгоритмов согласования общего ключа
            if (type == typeof(IKeyAgreement))
            {
                // указать неподдерживаемые алгоритмы
                if (oid == ASN1.ANSI.OID.x962_ec_public_key) return null; 
            }
            // для алгоритмов согласования общего ключа
            else if (type == typeof(ITransportAgreement))
            {
                // указать неподдерживаемые алгоритмы
                if (oid == ASN1.ANSI.OID.x963_ecdh_std_sha1             ) return null; 
                if (oid == ASN1.ANSI.OID.certicom_ecdh_std_sha2_224     ) return null; 
                if (oid == ASN1.ANSI.OID.certicom_ecdh_std_sha2_256     ) return null; 
                if (oid == ASN1.ANSI.OID.certicom_ecdh_std_sha2_384     ) return null; 
                if (oid == ASN1.ANSI.OID.certicom_ecdh_std_sha2_512     ) return null; 
                if (oid == ASN1.ANSI.OID.x963_ecdh_cofactor_sha1        ) return null; 
                if (oid == ASN1.ANSI.OID.certicom_ecdh_cofactor_sha2_224) return null; 
                if (oid == ASN1.ANSI.OID.certicom_ecdh_cofactor_sha2_256) return null; 
                if (oid == ASN1.ANSI.OID.certicom_ecdh_cofactor_sha2_384) return null; 
                if (oid == ASN1.ANSI.OID.certicom_ecdh_cofactor_sha2_512) return null; 
            }
            // вызвать базовую функцию
            return base.CreateAlgorithm(factory, scope, parameters, type); 
        }
    }
}
