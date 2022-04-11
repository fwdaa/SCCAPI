using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.RSA
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм генерации ключей RSA
    ///////////////////////////////////////////////////////////////////////////
    public class KeyPairGenerator : CAPI.PKCS11.KeyPairGenerator
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 
	    // параметры генерации
	    private ANSI.RSA.IParameters parameters; private ulong algID; 

	    // конструктор
	    public KeyPairGenerator(CAPI.PKCS11.Applet applet, SecurityObject scope, 
            IRand rand, ANSI.RSA.IParameters parameters, ulong algID)
	    
		    // сохранить переданные параметры
		    : base(applet, scope, rand) { this.parameters = parameters; this.algID = algID; }
	    
	    // сгенерировать пару ключей
	    public override KeyPair Generate(string keyOID, KeyUsage keyUsage)
        {
            // указать программный алгоритм генерации
            using (CAPI.KeyPairGenerator generator = new ANSI.RSA.KeyPairGenerator(
                Factory, Scope, Rand, parameters))
            { 
                // сгенерировать пару ключей
                return generator.Generate(null, keyOID, keyUsage, KeyFlags.None);  
            }
        }
	    // параметры алгоритма
        protected override Mechanism GetParameters(
            CAPI.PKCS11.Session sesssion, string keyOID)
	    {
		    // вернуть параметры алгоритма
		    return new Mechanism(algID); 
	    }
	    // атрибуты открытого ключа
        protected override CAPI.PKCS11.Attribute[] GetPublicAttributes(string keyOID) 
        { 
            // закодировать параметры генерации
            byte[] publicExponent = Math.Convert.FromBigInteger(parameters.PublicExponent, Endian);

            // создать список атрибутов
            return new CAPI.PKCS11.Attribute[] { 

                // указать размер модуля в битах
                Applet.Provider.CreateAttribute(API.CKA_MODULUS_BITS, (ulong)parameters.KeyBits), 
            
                // указать размер величину экспоненты
                Applet.Provider.CreateAttribute(API.CKA_PUBLIC_EXPONENT, publicExponent)    
            }; 
        } 
    }
}
