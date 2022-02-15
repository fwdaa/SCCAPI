using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.PBE
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования по паролю PKCS12 RC2-CBC
    ///////////////////////////////////////////////////////////////////////////
    public class PBESP12_RC2_CBC : CAPI.PKCS11.PBE.PBESP12
    {
        // эффективное число битов ключа
        private int effectiveKeyBits; 
    
	    // конструктор 
	    public PBESP12_RC2_CBC(CAPI.PKCS11.Applet applet, ulong algID, byte[] salt, int iterations)

            // сохранить переданные параметры
            : base(applet, algID, salt, iterations, Keys.RC2.Instance) 
        {
            // определить эффективное число битов ключа
            if (algID == API.CKM_PBE_SHA1_RC2_40_CBC ) effectiveKeyBits =  40; else 
            if (algID == API.CKM_PBE_SHA1_RC2_128_CBC) effectiveKeyBits = 128; 
            
            // при ошибке выбросить исключение
            throw new NotSupportedException(); 
	    }
        // размер блока алгоритма
	    public override int BlockSize { get { return 8; }}
	    // размер ключа
	    protected override int KeyLength { get { return (effectiveKeyBits + 7) / 8; }}  
    
	    // создать алгоритм шифрования
	    protected override CAPI.Cipher CreateCipher(byte[] iv)
        {
            // указать параметры алгоритма
            Mechanism parameters = new Mechanism(
                API.CKM_RC2_CBC_PAD, 
                new Parameters.CK_RC2_CBC_PARAMS(effectiveKeyBits, iv)
            ); 
            // создать алгоритм шифрования
            CAPI.Cipher cipher = Creator.CreateCipher(
                Applet.Provider, Applet, parameters, KeyLength
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
                Applet.Provider.CreateAttribute(API.CKA_VALUE_LEN, (uint)KeyLength) 
            }; 
        } 
    }
}
