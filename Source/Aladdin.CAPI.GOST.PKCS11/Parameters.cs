using System;
using System.Security;
using System.Security.Permissions;
using System.Runtime.InteropServices;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.GOST.PKCS11
{
    ///////////////////////////////////////////////////////////////////////////
    // Параметры механизмов
    ///////////////////////////////////////////////////////////////////////////
    public static class Parameters
    {
        ///////////////////////////////////////////////////////////////////////
        // Параметры алгоритмов согласования ГОСТ Р34.10
        ///////////////////////////////////////////////////////////////////////
        public class CK_GOSTR3410_DERIVE_PARAMS : MechanismParameters 
        {
            // параметры алгоритма
	        private ulong kdf; private byte[] publicData; private byte[] ukm;

            // конструктор
            public CK_GOSTR3410_DERIVE_PARAMS(ulong kdf, byte[] publicData, byte[] ukm)
            {
                // сохранить переданные параметры
                this.kdf = kdf; this.publicData = publicData; this.ukm = ukm; 
            }
            // определить требуемый размер буфера
            [SecuritySafeCritical]
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            public int GetBufferSize(Module module)
            {
                if (module.LongSize == 4)
                { 
                    // определить размер структуры
                    int total = Marshal.SizeOf(typeof(API32.CK_GOSTR3410_DERIVE_PARAMS)); 
                    
                    // вернуть требуемый размер
                    return total + publicData.Length + ukm.Length; 
                }
                else {
                    // определить размер структуры
                    int total = Marshal.SizeOf(typeof(API32.CK_GOSTR3410_DERIVE_PARAMS)); 
                    
                    // вернуть требуемый размер
                    return total + publicData.Length + ukm.Length; 
                }
            }
            // закодировать параметры
            [SecuritySafeCritical]
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            public object Encode(Module module, IntPtr ptr)
            {
                if (module.LongSize == 4)
                { 
                    API32.CK_GOSTR3410_DERIVE_PARAMS parameters; parameters.kdf = (uint)kdf; 

                    // инициализировать поле
                    parameters.pPublicData = IntPtr.Zero; parameters.pUKM = IntPtr.Zero; 
                    
                    // указать размер полей
                    parameters.ulPublicDataLen = publicData.Length; 
                    parameters.ulUKMLen        = ukm       .Length;

                    // определить адрес поля
                    parameters.pPublicData = new IntPtr(ptr.ToInt64() + Marshal.SizeOf(parameters)); 

                    // скопировать данные
                    Marshal.Copy(publicData, 0, parameters.pPublicData, publicData.Length); 

                    // определить адрес поля
                    parameters.pUKM = new IntPtr(parameters.pPublicData.ToInt64() + publicData.Length); 

                    // скопировать данные
                    Marshal.Copy(ukm, 0, parameters.pUKM, ukm.Length); return parameters; 
                }
                else { 
                    API64.CK_GOSTR3410_DERIVE_PARAMS parameters; parameters.kdf = kdf; 

                    // инициализировать поле
                    parameters.pPublicData = IntPtr.Zero; parameters.pUKM = IntPtr.Zero; 
                    
                    // указать размер полей
                    parameters.ulPublicDataLen = publicData.Length; 
                    parameters.ulUKMLen        = ukm       .Length;

                    // определить адрес поля
                    parameters.pPublicData = new IntPtr(ptr.ToInt64() + Marshal.SizeOf(parameters)); 

                    // скопировать данные
                    Marshal.Copy(publicData, 0, parameters.pPublicData, publicData.Length); 

                    // определить адрес поля
                    parameters.pUKM = new IntPtr(parameters.pPublicData.ToInt64() + publicData.Length); 

                    // скопировать данные
                    Marshal.Copy(ukm, 0, parameters.pUKM, ukm.Length); return parameters; 
                }
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Параметры алгоритмов шифрования ключа ГОСТ Р34.10
        ///////////////////////////////////////////////////////////////////////
        public class CK_GOSTR3410_KEY_WRAP_PARAMS : MechanismParameters 
        {
            // параметры алгоритма
	        private byte[] wrapOID; private byte[] ukm; private ulong hKey;

            // конструктор
            public CK_GOSTR3410_KEY_WRAP_PARAMS(byte[] wrapOID, byte[] ukm, ulong hKey)
            {
                // проверить наличие параметров
                if (wrapOID == null) wrapOID = new byte[0]; if (ukm == null) ukm = new byte[0];

                // сохранить переданные параметры
                this.wrapOID = wrapOID; this.ukm = ukm; this.hKey = hKey; 
            }
            // определить требуемый размер буфера
            [SecuritySafeCritical]
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            public int GetBufferSize(Module module)
            {
                if (module.LongSize == 4)
                { 
                    // определить размер структуры
                    int total = Marshal.SizeOf(typeof(API32.CK_GOSTR3410_KEY_WRAP_PARAMS)); 
                    
                    // вернуть требуемый размер
                    return total + wrapOID.Length + ukm.Length; 
                }
                else {
                    // определить размер структуры
                    int total = Marshal.SizeOf(typeof(API64.CK_GOSTR3410_KEY_WRAP_PARAMS)); 
                    
                    // вернуть требуемый размер
                    return total + wrapOID.Length + ukm.Length; 
                }
            }
            // закодировать параметры
            [SecuritySafeCritical]
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            public object Encode(Module module, IntPtr ptr)
            {
                if (module.LongSize == 4)
                { 
                    API32.CK_GOSTR3410_KEY_WRAP_PARAMS parameters; parameters.hKey = (uint)hKey; 

                    // инициализировать поле
                    parameters.pWrapOID = IntPtr.Zero; parameters.pUKM = IntPtr.Zero; 
                    
                    // указать размер полей
                    parameters.ulWrapOIDLen = wrapOID.Length; 
                    parameters.ulUKMLen     = ukm    .Length;

                    // пропустить размер структуры
                    ptr = new IntPtr(ptr.ToInt64() + Marshal.SizeOf(parameters)); 

                    // при наличии данных
                    if (wrapOID.Length != 0)
                    {
                        // определить адрес поля
                        parameters.pWrapOID = ptr; ptr = new IntPtr(ptr.ToInt64() + wrapOID.Length); 

                        // скопировать данные
                        Marshal.Copy(wrapOID, 0, parameters.pWrapOID, wrapOID.Length); 
                    }
                    // при наличии данных
                    if (ukm.Length != 0)
                    {
                        // определить адрес поля
                        parameters.pUKM = ptr; ptr = new IntPtr(ptr.ToInt64() + ukm.Length); 

                        // скопировать данные
                        Marshal.Copy(ukm, 0, parameters.pUKM, ukm.Length); 
                    }
                    return parameters; 
                }
                else { 
                    API64.CK_GOSTR3410_KEY_WRAP_PARAMS parameters; parameters.hKey = hKey; 

                    // инициализировать поле
                    parameters.pWrapOID = IntPtr.Zero; parameters.pUKM = IntPtr.Zero; 
                    
                    // указать размер полей
                    parameters.ulWrapOIDLen = wrapOID.Length; 
                    parameters.ulUKMLen     = ukm    .Length;

                    // пропустить размер структуры
                    ptr = new IntPtr(ptr.ToInt64() + Marshal.SizeOf(parameters)); 

                    // при наличии данных
                    if (wrapOID.Length != 0)
                    {
                        // определить адрес поля
                        parameters.pWrapOID = ptr; ptr = new IntPtr(ptr.ToInt64() + wrapOID.Length); 

                        // скопировать данные
                        Marshal.Copy(wrapOID, 0, parameters.pWrapOID, wrapOID.Length); 
                    }
                    // при наличии данных
                    if (ukm.Length != 0)
                    {
                        // определить адрес поля
                        parameters.pUKM = ptr; ptr = new IntPtr(ptr.ToInt64() + ukm.Length); 

                        // скопировать данные
                        Marshal.Copy(ukm, 0, parameters.pUKM, ukm.Length); 
                    }
                    return parameters; 
                }
            }
        }
    }
}
