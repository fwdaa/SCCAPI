using System;
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
            module = Module.Create(new NativeMethods.NativeAPI()); 
        }
        // деструктор
        protected override void OnDispose() 
        {
            // освободить выделенные ресурсы
            RefObject.Release(module); base.OnDispose(); 
        } 
		// интерфейс вызова функций
		public override Module Module { get { return module; }} private Module module;

        // корректная реализация отдельных OAEP механизмов
        public override bool UseOAEP(Applet applet, 
            ANSI.PKCS11.Parameters.CK_RSA_PKCS_OAEP_PARAMS parameters) 
        { 
            // проверить корректность реализации
            return (parameters.HashAlg == API.CKM_SHA_1 && parameters.MGF == API.CKG_MGF1_SHA1); 
        }
        // некорректная реализация PSS механизмов
        public override bool UsePSS(Applet applet, 
            ANSI.PKCS11.Parameters.CK_RSA_PKCS_PSS_PARAMS parameters) { return false; }

	    // создать алгоритм для параметров
	    protected override IAlgorithm CreateAlgorithm(CAPI.Factory factory, 
            SecurityStore scope, string oid, ASN1.IEncodable parameters, Type type)
        {
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
            return base.CreateAlgorithm(factory, scope, oid, parameters, type); 
        }
    }
}
