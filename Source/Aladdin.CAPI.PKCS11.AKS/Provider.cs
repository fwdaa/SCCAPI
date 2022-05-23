using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11.AKS
{
	///////////////////////////////////////////////////////////////////////////
	// Криптографический провайдер
	///////////////////////////////////////////////////////////////////////////
	public sealed class Provider : ANSI.PKCS11.Provider
	{
		// конструктор
		public Provider() : base("eToken PKCS11 Cryptographic Provider", false) 
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

        // тип структуры передачи параметров механизма PBKDF2
        protected override PBE.PBKDF2.ParametersType PBKDF2ParametersType 
        {
            // тип структуры передачи параметров механизма PBKDF2
            get { return PBE.PBKDF2.ParametersType.ParamsLong; }
        }
    }
}
