using System;
using System.Security;
using System.Security.Permissions;
using System.Runtime.InteropServices;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11
{
    ///////////////////////////////////////////////////////////////////////////
    // Параметры алгоритмов
    ///////////////////////////////////////////////////////////////////////////
    internal static class Parameters
    {
        ///////////////////////////////////////////////////////////////////////
        // Параметры алгоритмов PBE
        ///////////////////////////////////////////////////////////////////////
        public class CK_PBE_PARAMS : MechanismParameters 
        {
            public readonly IntPtr IV;         // [out] pointer to the 8-byte initialization vector
            public readonly byte[] Password;   // password to be used in the PBE key generation
            public readonly byte[] Salt;       // salt to be used in the PBE key generation
            public readonly int    Iterations; // number of iterations required for the generation

            // конструктор
            public CK_PBE_PARAMS(IntPtr iv, byte[]  password, byte[] salt, int iterations)
            {
                // сохранить переданные параметры
                IV = iv; Password = password; Iterations = iterations;
                
                // сохранить переданные параметры
                Salt = (salt != null) ? salt : new byte[0]; 
            }
            // определить требуемый размер буфера
            public int GetBufferSize(Module module)
            {
                if (module.LongSize == 4)
                { 
                    // определить размер структуры
                    int total = Marshal.SizeOf(typeof(API32.CK_PBE_PARAMS)); 
                    
                    // вернуть требуемый размер
                    return total + Password.Length + Salt.Length; 
                }
                else {
                    // определить размер структуры
                    int total = Marshal.SizeOf(typeof(API64.CK_PBE_PARAMS)); 
                    
                    // вернуть требуемый размер
                    return total + Password.Length + Salt.Length; 
                }
            }
            // закодировать параметры
            [SecuritySafeCritical]
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            public object Encode(Module module, IntPtr ptr)
            {
                if (module.LongSize == 4)
                { 
                    API32.CK_PBE_PARAMS parameters; 
                    
                    // указать адрес выходной синхропосылки
                    parameters.pInitVector = IV; parameters.ulIteration = Iterations;

                    // инициализировать переменные
                    parameters.pPassword = IntPtr.Zero; parameters.pSalt = IntPtr.Zero; 
                        
                    // указать параметры
                    parameters.ulPasswordLen = Password.Length; 
                    parameters.ulSaltLen     = Salt    .Length;

                    // определить адрес буфера
                    parameters.pPassword = new IntPtr(ptr.ToInt64() + Marshal.SizeOf(parameters)); 

                    // скопировать пароль
                    Marshal.Copy(Password, 0, parameters.pPassword, Password.Length); 
                    
                    // определить адрес буфера
                    parameters.pSalt = new IntPtr(parameters.pPassword.ToInt64() + Password.Length); 

                    // скопировать salt-значение
                    Marshal.Copy(Salt, 0, parameters.pSalt, Salt.Length); return parameters; 
                }
                else { 
                    API64.CK_PBE_PARAMS parameters; 
                    
                    // указать адрес выходной синхропосылки
                    parameters.pInitVector = IV; parameters.ulIteration = Iterations;

                    // инициализировать переменные
                    parameters.pPassword = IntPtr.Zero; parameters.pSalt = IntPtr.Zero; 
                        
                    // указать параметры
                    parameters.ulPasswordLen = Password.Length; 
                    parameters.ulSaltLen     = Salt    .Length;

                    // определить адрес буфера
                    parameters.pPassword = new IntPtr(ptr.ToInt64() + Marshal.SizeOf(parameters)); 

                    // скопировать пароль
                    Marshal.Copy(Password, 0, parameters.pPassword, Password.Length); 
                    
                    // определить адрес буфера
                    parameters.pSalt = new IntPtr(parameters.pPassword.ToInt64() + Password.Length); 

                    // скопировать salt-значение
                    Marshal.Copy(Salt, 0, parameters.pSalt, Salt.Length); return parameters; 
                }
            }
        }
        public class CK_PKCS5_PBKD2_PARAMS : MechanismParameters 
        {
            public readonly bool   HasPointer;  // признак наличия указателя
            public readonly ulong  PRF;         // pseudo-random function used to generate the key
            public readonly byte[] PRFData;     // data used as the input for PRF in addition to the salt value
            public readonly byte[] Password;    // password to be used in the PBE key generation
            public readonly byte[] Salt;        // salt to be used in the PBE key generation
            public readonly int    Iterations;  // number of iterations required for the generation

            // конструктор
            public CK_PKCS5_PBKD2_PARAMS(bool hasPointer, 
                ulong prf, byte[] prfData, byte[] password, byte[] salt, int iterations)
            {
                // сохранить переданные параметры
                PRF = prf; Password = password; Iterations = iterations;
                
                // сохранить переданные параметры
                PRFData = (prfData != null) ? prfData : new byte[0]; 
                
                // сохранить переданные параметры
                Salt = (salt != null) ? salt : new byte[0]; HasPointer = hasPointer; 
            }
            // определить требуемый размер буфера
            public int GetBufferSize(Module module)
            {
                if (module.LongSize == 4)
                { 
                    // определить размер структуры
                    int total = Marshal.SizeOf(typeof(API32.CK_PKCS5_PBKD2_PARAMS)); 
                    
                    // вернуть требуемый размер
                    return total + PRFData.Length + Password.Length + Salt.Length + 4; 
                }
                else {
                    // определить размер структуры
                    int total = Marshal.SizeOf(typeof(API64.CK_PKCS5_PBKD2_PARAMS)); 
                    
                    // вернуть требуемый размер
                    return total + PRFData.Length + Password.Length + Salt.Length + 8; 
                }
            }
            // закодировать параметры
            [SecuritySafeCritical]
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            public object Encode(Module module, IntPtr ptr)
            {
                if (module.LongSize == 4)
                { 
                    API32.CK_PKCS5_PBKD2_PARAMS parameters; parameters.saltSource = 0; 
                    
                    // указать параметры
                    parameters.prf = (uint)PRF; parameters.iterations = Iterations;

                    // инициализировать переменные
                    parameters.pPrfData = IntPtr.Zero; parameters.ulPrfDataLen = PRFData.Length; 

                    // инициализировать переменные
                    parameters.pPassword = IntPtr.Zero; parameters.pSaltSourceData = IntPtr.Zero; 
                        
                    // указать параметры
                    parameters.pulPasswordLen      = new IntPtr(Password.Length); 
                    parameters.ulSaltSourceDataLen = Salt.Length;

                    // пропустить структуру
                    ptr = new IntPtr(ptr.ToInt64() + Marshal.SizeOf(parameters)); if (HasPointer)
                    { 
                        // закодировать размер
                        byte[] encodedLength = module.EncodeLong((ulong)Password.Length);  

                        // определить адрес буфера
                        parameters.pulPasswordLen = ptr; ptr = new IntPtr(ptr.ToInt64() + module.LongSize);

                        // скопировать размер
                        Marshal.Copy(encodedLength, 0, parameters.pulPasswordLen, module.LongSize); 
                    }
                    if (PRFData.Length > 0)
                    { 
                        // определить адрес буфера
                        parameters.pPrfData = ptr; ptr = new IntPtr(ptr.ToInt64() + PRFData.Length); 

                        // скопировать параметры 
                        Marshal.Copy(PRFData, 0, parameters.pPrfData, PRFData.Length); 
                    }
                    // определить адрес буфера
                    parameters.pPassword = ptr; ptr = new IntPtr(ptr.ToInt64() + Password.Length); 

                    // скопировать пароль
                    Marshal.Copy(Password, 0, parameters.pPassword, Password.Length); 

                    // проверить наличие случайных данных
                    if (Salt == null || Salt.Length == 0) return parameters; 
                    
                    // определить адрес буфера
                    parameters.pSaltSourceData = ptr; ptr = new IntPtr(ptr.ToInt64() + Salt.Length); 

                    // скопировать salt-значение
                    Marshal.Copy(Salt, 0, parameters.pSaltSourceData, Salt.Length); 
                    
                    // указать наличие данных
                    parameters.saltSource = API.CKZ_SALT_SPECIFIED; return parameters; 
                }
                else { 
                    API64.CK_PKCS5_PBKD2_PARAMS parameters; parameters.saltSource = 0; 
                    
                    // указать параметры
                    parameters.prf = (uint)PRF; parameters.iterations = Iterations;

                    // инициализировать переменные
                    parameters.pPrfData = IntPtr.Zero; parameters.ulPrfDataLen = PRFData.Length; 

                    // инициализировать переменные
                    parameters.pPassword = IntPtr.Zero; parameters.pSaltSourceData = IntPtr.Zero; 
                        
                    // указать параметры
                    parameters.pulPasswordLen      = new IntPtr(Password.Length); 
                    parameters.ulSaltSourceDataLen = Salt.Length;

                    // пропустить структуру
                    ptr = new IntPtr(ptr.ToInt64() + Marshal.SizeOf(parameters)); if (HasPointer)
                    { 
                        // закодировать размер
                        byte[] encodedLength = module.EncodeLong((ulong)Password.Length);  

                        // определить адрес буфера
                        parameters.pulPasswordLen = ptr; ptr = new IntPtr(ptr.ToInt64() + module.LongSize);

                        // скопировать размер
                        Marshal.Copy(encodedLength, 0, parameters.pulPasswordLen, module.LongSize); 
                    }
                    if (PRFData.Length > 0)
                    { 
                        // определить адрес буфера
                        parameters.pPrfData = ptr; ptr = new IntPtr(ptr.ToInt64() + PRFData.Length); 

                        // скопировать параметры 
                        Marshal.Copy(PRFData, 0, parameters.pPrfData, PRFData.Length); 
                    }
                    // определить адрес буфера
                    parameters.pPassword = ptr; ptr = new IntPtr(ptr.ToInt64() + Password.Length); 

                    // скопировать пароль
                    Marshal.Copy(Password, 0, parameters.pPassword, Password.Length); 

                    // проверить наличие случайных данных
                    if (Salt == null || Salt.Length == 0) return parameters; 
                    
                    // определить адрес буфера
                    parameters.pSaltSourceData = ptr; ptr = new IntPtr(ptr.ToInt64() + Salt.Length); 

                    // скопировать salt-значение
                    Marshal.Copy(Salt, 0, parameters.pSaltSourceData, Salt.Length); 
                    
                    // указать наличие данных
                    parameters.saltSource = API.CKZ_SALT_SPECIFIED; return parameters; 
                }
            }
        }
        public class CK_PKCS5_PBKD2_PARAMS2 : MechanismParameters 
        {
            public readonly ulong  PRF;         // pseudo-random function used to generate the key
            public readonly byte[] PRFData;     // data used as the input for PRF in addition to the salt value
            public readonly byte[] Password;    // password to be used in the PBE key generation
            public readonly byte[] Salt;        // salt to be used in the PBE key generation
            public readonly int    Iterations;  // number of iterations required for the generation

            // конструктор
            public CK_PKCS5_PBKD2_PARAMS2(ulong prf, byte[] prfData, 
                byte[] password, byte[] salt, int iterations)
            {
                // сохранить переданные параметры
                PRF = prf; Password = password; Iterations = iterations;
                
                // сохранить переданные параметры
                PRFData = (prfData != null) ? prfData : new byte[0]; 
                
                // сохранить переданные параметры
                Salt = (salt != null) ? salt : new byte[0]; 
            }
            // определить требуемый размер буфера
            public int GetBufferSize(Module module)
            {
                if (module.LongSize == 4)
                { 
                    // определить размер структуры
                    int total = Marshal.SizeOf(typeof(API32.CK_PKCS5_PBKD2_PARAMS2)); 
                    
                    // вернуть требуемый размер
                    return total + PRFData.Length + Password.Length + Salt.Length; 
                }
                else {
                    // определить размер структуры
                    int total = Marshal.SizeOf(typeof(API64.CK_PKCS5_PBKD2_PARAMS2)); 
                    
                    // вернуть требуемый размер
                    return total + PRFData.Length + Password.Length + Salt.Length; 
                }
            }
            // закодировать параметры
            [SecuritySafeCritical]
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            public object Encode(Module module, IntPtr ptr)
            {
                if (module.LongSize == 4)
                { 
                    API32.CK_PKCS5_PBKD2_PARAMS2 parameters; parameters.saltSource = 0; 
                    
                    // указать параметры
                    parameters.prf = (uint)PRF; parameters.iterations = Iterations;

                    // инициализировать переменные
                    parameters.pPrfData = IntPtr.Zero; parameters.ulPrfDataLen = PRFData.Length; 

                    // инициализировать переменные
                    parameters.pPassword = IntPtr.Zero; parameters.pSaltSourceData = IntPtr.Zero; 
                        
                    // указать параметры
                    parameters.ulPasswordLen       = Password.Length; 
                    parameters.ulSaltSourceDataLen = Salt    .Length;

                    // пропустить структуру
                    ptr = new IntPtr(ptr.ToInt64() + Marshal.SizeOf(parameters)); if (PRFData.Length > 0)
                    { 
                        // определить адрес буфера
                        parameters.pPrfData = ptr; ptr = new IntPtr(ptr.ToInt64() + PRFData.Length); 

                        // скопировать параметры 
                        Marshal.Copy(PRFData, 0, parameters.pPrfData, PRFData.Length); 
                    }
                    // определить адрес буфера
                    parameters.pPassword = ptr; ptr = new IntPtr(ptr.ToInt64() + Password.Length); 

                    // скопировать пароль
                    Marshal.Copy(Password, 0, parameters.pPassword, Password.Length); 

                    // проверить наличие случайных данных
                    if (Salt == null || Salt.Length == 0) return parameters; 
                    
                    // определить адрес буфера
                    parameters.pSaltSourceData = ptr; ptr = new IntPtr(ptr.ToInt64() + Salt.Length); 

                    // скопировать salt-значение
                    Marshal.Copy(Salt, 0, parameters.pSaltSourceData, Salt.Length); 
                    
                    // указать наличие данных
                    parameters.saltSource = API.CKZ_SALT_SPECIFIED; return parameters; 
                }
                else { 
                    API64.CK_PKCS5_PBKD2_PARAMS2 parameters; parameters.saltSource = 0; 
                    
                    // указать параметры
                    parameters.prf = (uint)PRF; parameters.iterations = Iterations;

                    // инициализировать переменные
                    parameters.pPrfData = IntPtr.Zero; parameters.ulPrfDataLen = PRFData.Length; 

                    // инициализировать переменные
                    parameters.pPassword = IntPtr.Zero; parameters.pSaltSourceData = IntPtr.Zero; 
                        
                    // указать параметры
                    parameters.ulPasswordLen       = Password.Length; 
                    parameters.ulSaltSourceDataLen = Salt    .Length;

                    // пропустить структуру
                    ptr = new IntPtr(ptr.ToInt64() + Marshal.SizeOf(parameters)); if (PRFData.Length > 0)
                    { 
                        // определить адрес буфера
                        parameters.pPrfData = ptr; ptr = new IntPtr(ptr.ToInt64() + PRFData.Length); 

                        // скопировать параметры 
                        Marshal.Copy(PRFData, 0, parameters.pPrfData, PRFData.Length); 
                    }
                    // определить адрес буфера
                    parameters.pPassword = ptr; ptr = new IntPtr(ptr.ToInt64() + Password.Length); 

                    // скопировать пароль
                    Marshal.Copy(Password, 0, parameters.pPassword, Password.Length); 

                    // проверить наличие случайных данных
                    if (Salt == null || Salt.Length == 0) return parameters; 
                    
                    // определить адрес буфера
                    parameters.pSaltSourceData = ptr; ptr = new IntPtr(ptr.ToInt64() + Salt.Length); 

                    // скопировать salt-значение
                    Marshal.Copy(Salt, 0, parameters.pSaltSourceData, Salt.Length); 
                    
                    // указать наличие данных
                    parameters.saltSource = API.CKZ_SALT_SPECIFIED; return parameters; 
                }
            }
        }
    }
}
