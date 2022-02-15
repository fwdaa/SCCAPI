using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.PBE
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования по паролю PKCS12 RC4
    ///////////////////////////////////////////////////////////////////////////
    public class PBESP12_RC4 : CAPI.PKCS11.PBE.PBESP12
    {
        // размер ключа
        private int keyLength; 

	    // конструктор 
	    public PBESP12_RC4(CAPI.PKCS11.Applet applet, ulong algID, byte[] salt, int iterations)
	    
            // сохранить переданные параметры
            : base(applet, algID, salt, iterations, Keys.RC4.Instance) 
        {
            // определить эффективное число битов ключа
            if (algID == API.CKM_PBE_SHA1_RC4_128) keyLength = 16; else 
            if (algID == API.CKM_PBE_SHA1_RC4_40 ) keyLength =  5; 
            
            // при ошибке выбросить исключение
            else throw new NotSupportedException(); 
        } 
	    // размер ключа
	    protected override int KeyLength { get { return keyLength; }}  

	    // создать алгоритм шифрования
	    protected override CAPI.Cipher CreateCipher(byte[] iv) 
        {
            // указать параметры алгоритма
            Mechanism parameters = 
                new Mechanism(API.CKM_RC4); 
        
            // создать алгоритм шифрования
            CAPI.Cipher cipher = Creator.CreateCipher(
                Applet.Provider, Applet, parameters, keyLength
            ); 
            // проверить наличие алгоритма
            if (cipher == null) throw new NotSupportedException(); return cipher; 
        }
	    // атрибуты ключа
	    public override CAPI.PKCS11.Attribute[] GetKeyAttributes() 
        { 
            // дополнительные атрибуты ключа
            return new CAPI.PKCS11.Attribute[] {
                Applet.Provider.CreateAttribute(API.CKA_KEY_TYPE , API.CKK_RC2    ), 
                Applet.Provider.CreateAttribute(API.CKA_VALUE_LEN, (uint)keyLength) 
            }; 
        } 
    }
}
