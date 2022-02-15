using System;
using System.Security;
using System.Security.Permissions;
using System.Runtime.InteropServices;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11
{
    ///////////////////////////////////////////////////////////////////////////
    // Параметры алгоритмов
    ///////////////////////////////////////////////////////////////////////////
    public static class Parameters
    {
        ///////////////////////////////////////////////////////////////////////
        // Параметры алгоритмов RC2
        ///////////////////////////////////////////////////////////////////////
        public class CK_RC2_CBC_PARAMS : MechanismParameters 
        {
            // параметры алгоритма
            public readonly int EffectiveBits; public readonly byte[] IV;           

            // конструктор
            public CK_RC2_CBC_PARAMS(int effectiveBits, byte[] iv)
            {
                // сохранить переданные параметры
                EffectiveBits = effectiveBits; IV = iv; 
            }
            // определить требуемый размер буфера
            [SecuritySafeCritical]
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            public int GetBufferSize(Module module)
            {
                if (module.LongSize == 4) 
                {
                    // вернуть требуемый размер
                    return Marshal.SizeOf(typeof(API32.CK_RC2_CBC_PARAMS)); 
                }
                else {
                    // вернуть требуемый размер
                    return Marshal.SizeOf(typeof(API64.CK_RC2_CBC_PARAMS)); 
                }
            }
            // закодировать параметры
            public object Encode(Module module, IntPtr ptr)
            {
                if (module.LongSize == 4) 
                {
                    // указать параметры
                    API32.CK_RC2_CBC_PARAMS parameters; parameters.iv = new byte[8]; 
                
                    // указать параметры
                    parameters.ulEffectiveBits = EffectiveBits;

                    // скопировать синхропосылку
                    Array.Copy(IV, 0, parameters.iv, 0, 8); return parameters; 
                }
                else {
                    // указать параметры
                    API64.CK_RC2_CBC_PARAMS parameters; parameters.iv = new byte[8]; 
                
                    // указать параметры
                    parameters.ulEffectiveBits = EffectiveBits;

                    // скопировать синхропосылку
                    Array.Copy(IV, 0, parameters.iv, 0, 8); return parameters; 
                }
            }
        }
        public class CK_RC2_MAC_GENERAL_PARAMS : MechanismParameters 
        {
            // параметры алгоритма
            public readonly int EffectiveBits; public readonly int MacLength;

            // конструктор
            public CK_RC2_MAC_GENERAL_PARAMS(int effectiveBits, int macLength)
            {
                // сохранить переданные параметры
                EffectiveBits = effectiveBits; MacLength = macLength; 
            }
            // определить требуемый размер буфера
            [SecuritySafeCritical]
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            public int GetBufferSize(Module module)
            {
                if (module.LongSize == 4) 
                {
                    // вернуть требуемый размер
                    return Marshal.SizeOf(typeof(API32.CK_RC2_MAC_GENERAL_PARAMS)); 
                }
                else {
                    // вернуть требуемый размер
                    return Marshal.SizeOf(typeof(API64.CK_RC2_MAC_GENERAL_PARAMS)); 
                }
            }
            // закодировать параметры
            public object Encode(Module module, IntPtr ptr)
            {
                if (module.LongSize == 4) 
                {
                    API32.CK_RC2_MAC_GENERAL_PARAMS parameters; 
                
                    // указать параметры
                    parameters.ulEffectiveBits = EffectiveBits;

                    // указать параметры
                    parameters.ulMacLength = MacLength; return parameters; 
                }
                else {
                    API64.CK_RC2_MAC_GENERAL_PARAMS parameters; 
                
                    // указать параметры
                    parameters.ulEffectiveBits = EffectiveBits;

                    // указать параметры
                    parameters.ulMacLength = MacLength; return parameters; 
                }
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Параметры алгоритмов RC5
        ///////////////////////////////////////////////////////////////////////
        public class CK_RC5_PARAMS : MechanismParameters 
        {
            // параметры алгоритма
            public readonly int WordSize; public readonly int Rounds;   

            // конструктор
            public CK_RC5_PARAMS(int wordsize, int rounds)
            {
                // сохранить переданные параметры
                WordSize = wordsize; Rounds = rounds; 
            }
            // определить требуемый размер буфера
            [SecuritySafeCritical]
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            public int GetBufferSize(Module module)
            {
                if (module.LongSize == 4) 
                {
                    // вернуть требуемый размер
                    return Marshal.SizeOf(typeof(API32.CK_RC5_PARAMS)); 
                }
                else {
                    // вернуть требуемый размер
                    return Marshal.SizeOf(typeof(API64.CK_RC5_PARAMS)); 
                }
            }
            // закодировать параметры
            public object Encode(Module module, IntPtr ptr)
            {
                if (module.LongSize == 4) 
                {
                    API32.CK_RC5_PARAMS parameters; 
                
                    // указать параметры
                    parameters.ulWordsize = WordSize;

                    // указать параметры
                    parameters.ulRounds = Rounds; return parameters; 
                }
                else {
                    API64.CK_RC5_PARAMS parameters; 
                
                    // указать параметры
                    parameters.ulWordsize = WordSize;

                    // указать параметры
                    parameters.ulRounds = Rounds; return parameters; 
                }
            }
        }
        public class CK_RC5_CBC_PARAMS : MechanismParameters 
        {
            // параметры алгоритма
            public readonly int WordSize; public readonly int Rounds; public readonly byte[] IV;

            // конструктор
            public CK_RC5_CBC_PARAMS(int wordsize, int rounds, byte[] iv)
            {
                // сохранить переданные параметры
                WordSize = wordsize; Rounds = rounds; IV = iv; 
            }
            // определить требуемый размер буфера
            [SecuritySafeCritical]
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            public int GetBufferSize(Module module)
            {
                if (module.LongSize == 4) 
                {
                    // определить размер структуры
                    int total = Marshal.SizeOf(typeof(API32.CK_RC5_CBC_PARAMS)); 
                    
                    // вернуть общий размер
                    return total + IV.Length; 
                }
                else {
                    // определить размер структуры
                    int total = Marshal.SizeOf(typeof(API64.CK_RC5_CBC_PARAMS)); 
                    
                    // вернуть общий размер
                    return total + IV.Length; 
                }
            }
            // закодировать параметры
            [SecuritySafeCritical]
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            public object Encode(Module module, IntPtr ptr)
            {
                if (module.LongSize == 4) 
                {
                    API32.CK_RC5_CBC_PARAMS parameters; 

                    // указать размер синхропосылки
                    parameters.pIv = IntPtr.Zero; parameters.ulIvLen = IV.Length; 
                        
                    // указать параметры
                    parameters.ulWordsize = WordSize; parameters.ulRounds = Rounds;

                    // определить адрес синхропосылки
                    parameters.pIv = new IntPtr(ptr.ToInt64() + Marshal.SizeOf(parameters)); 

                    // скопировать синхропосылку
                    Marshal.Copy(IV, 0, parameters.pIv, IV.Length); return parameters; 
                }
                else {
                    API64.CK_RC5_CBC_PARAMS parameters; 

                    // указать размер синхропосылки
                    parameters.pIv = IntPtr.Zero; parameters.ulIvLen = IV.Length; 
                        
                    // указать параметры
                    parameters.ulWordsize = WordSize; parameters.ulRounds = Rounds;

                    // определить адрес синхропосылки
                    parameters.pIv = new IntPtr(ptr.ToInt64() + Marshal.SizeOf(parameters)); 

                    // скопировать синхропосылку
                    Marshal.Copy(IV, 0, parameters.pIv, IV.Length); return parameters; 
                }
            }
        }
        public class CK_RC5_MAC_GENERAL_PARAMS : MechanismParameters 
        {
            // параметры алгоритма
            public readonly int WordSize; public readonly int Rounds; public readonly int MacLength;

            // конструктор
            public CK_RC5_MAC_GENERAL_PARAMS(int wordsize, int rounds, int macLength)
            {
                // сохранить переданные параметры
                WordSize = wordsize; Rounds = rounds; MacLength = macLength; 
            }
            // определить требуемый размер буфера
            [SecuritySafeCritical]
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            public int GetBufferSize(Module module)
            {
                if (module.LongSize == 4)
                { 
                    // вернуть требуемый размер
                    return Marshal.SizeOf(typeof(API32.CK_RC5_MAC_GENERAL_PARAMS)); 
                }
                else {
                    // вернуть требуемый размер
                    return Marshal.SizeOf(typeof(API64.CK_RC5_MAC_GENERAL_PARAMS));
                }
            }
            // закодировать параметры
            public object Encode(Module module, IntPtr ptr)
            {
                if (module.LongSize == 4)
                { 
                    API32.CK_RC5_MAC_GENERAL_PARAMS parameters; 
                
                    // указать параметры
                    parameters.ulWordsize = WordSize; parameters.ulRounds = Rounds;

                    // указать параметры
                    parameters.ulMacLength = MacLength; return parameters; 
                }
                else { 
                    API64.CK_RC5_MAC_GENERAL_PARAMS parameters; 
                
                    // указать параметры
                    parameters.ulWordsize = WordSize; parameters.ulRounds = Rounds;

                    // указать параметры
                    parameters.ulMacLength = MacLength; return parameters; 
                }
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Параметры алгоритмов AES
        ///////////////////////////////////////////////////////////////////////
        public class CK_AES_CTR_PARAMS : MechanismParameters 
        {
            // параметры алгоритма
            public readonly byte[] IV; public readonly int CounterBits; 

            // конструктор
            public CK_AES_CTR_PARAMS(byte[] iv, int counterBits)
            {
                // сохранить переданные параметры
                IV = iv; CounterBits = counterBits; 
            }
            // определить требуемый размер буфера
            [SecuritySafeCritical]
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            public int GetBufferSize(Module module)
            {
                if (module.LongSize == 4) 
                {
                    // вернуть требуемый размер
                    return Marshal.SizeOf(typeof(API32.CK_AES_CTR_PARAMS)); 
                }
                else {
                    // вернуть требуемый размер
                    return Marshal.SizeOf(typeof(API64.CK_AES_CTR_PARAMS)); 
                }
            }
            // закодировать параметры
            public object Encode(Module module, IntPtr ptr)
            {
                if (module.LongSize == 4) 
                {
                    // указать параметры
                    API32.CK_AES_CTR_PARAMS parameters; parameters.cb = new byte[16]; 
                
                    // указать параметры
                    parameters.ulCounterBits = CounterBits;

                    // скопировать синхропосылку
                    Array.Copy(IV, 0, parameters.cb, 0, 16); return parameters; 
                }
                else {
                    // указать параметры
                    API64.CK_AES_CTR_PARAMS parameters; parameters.cb = new byte[16]; 
                
                    // указать параметры
                    parameters.ulCounterBits = CounterBits;

                    // скопировать синхропосылку
                    Array.Copy(IV, 0, parameters.cb, 0, 16); return parameters; 
                }
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Параметры алгоритмов RSA
        ///////////////////////////////////////////////////////////////////////
        public class CK_RSA_PKCS_OAEP_PARAMS : MechanismParameters 
        {
            // параметры алгоритма
            public readonly ulong HashAlg; public readonly ulong MGF; public readonly byte[] SourceData;

            // конструктор
            public CK_RSA_PKCS_OAEP_PARAMS(ulong hashAlg, ulong mgf, byte[] sourceData)
            {
                // сохранить переданные параметры
                HashAlg = hashAlg; MGF = mgf; SourceData = sourceData; 

                // проверить указание данных
                if (sourceData == null) SourceData = new byte[0]; 
            }
            // определить требуемый размер буфера
            [SecuritySafeCritical]
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            public int GetBufferSize(Module module)
            {
                if (module.LongSize == 4)
                { 
                    // определить размер структуры
                    int total = Marshal.SizeOf(typeof(API32.CK_RSA_PKCS_OAEP_PARAMS)); 
                    
                    // вернуть требуемый размер
                    return total + SourceData.Length; 
                }
                else {
                    // определить размер структуры
                    int total = Marshal.SizeOf(typeof(API64.CK_RSA_PKCS_OAEP_PARAMS)); 
                    
                    // вернуть требуемый размер
                    return total + SourceData.Length; 
                }
            }
            // закодировать параметры
            [SecuritySafeCritical]
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            public object Encode(Module module, IntPtr ptr)
            {
                if (module.LongSize == 4)
                { 
                    API32.CK_RSA_PKCS_OAEP_PARAMS parameters; 

                    // инициализировать поле
                    parameters.source = 0; parameters.pSourceData = IntPtr.Zero; 
                    
                    // указать параметры
                    parameters.hashAlg = (uint)HashAlg; parameters.mgf = (uint)MGF;

                    // указать размер данных
                    parameters.ulSourceDataLen = SourceData.Length; 

                    // проверить наличие данных
                    if (SourceData == null || SourceData.Length == 0) return parameters; 

                    // определить адрес синхропосылки
                    parameters.pSourceData = new IntPtr(ptr.ToInt64() + Marshal.SizeOf(parameters)); 

                    // скопировать данные
                    Marshal.Copy(SourceData, 0, parameters.pSourceData, SourceData.Length); 

                    // указать наличие данных
                    parameters.source = API.CKZ_DATA_SPECIFIED; return parameters; 
                }
                else { 
                    API64.CK_RSA_PKCS_OAEP_PARAMS parameters; 

                    // инициализировать поле
                    parameters.source = 0; parameters.pSourceData = IntPtr.Zero; 
                    
                    // указать параметры
                    parameters.hashAlg = HashAlg; parameters.mgf = MGF;

                    // указать размер данных
                    parameters.ulSourceDataLen = SourceData.Length; 

                    // проверить наличие данных
                    if (SourceData == null || SourceData.Length == 0) return parameters; 

                    // определить адрес синхропосылки
                    parameters.pSourceData = new IntPtr(ptr.ToInt64() + Marshal.SizeOf(parameters)); 

                    // скопировать данные
                    Marshal.Copy(SourceData, 0, parameters.pSourceData, SourceData.Length); 

                    // указать наличие данных
                    parameters.source = API.CKZ_DATA_SPECIFIED; return parameters; 
                }
            }
        }
        public class CK_RSA_PKCS_PSS_PARAMS : MechanismParameters 
        {
            // параметры алгоритма
            public readonly ulong HashAlg; public readonly ulong MGF; public readonly int SaltLength;

            // конструктор
            public CK_RSA_PKCS_PSS_PARAMS(ulong hashAlg, ulong mgf, int sLen)
            {
                // сохранить переданные параметры
                HashAlg = hashAlg; MGF = mgf; SaltLength = sLen; 
            }
            // определить требуемый размер буфера
            [SecuritySafeCritical]
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            public int GetBufferSize(Module module)
            {
                if (module.LongSize == 4)
                { 
                    // вернуть требуемый размер
                    return Marshal.SizeOf(typeof(API32.CK_RSA_PKCS_PSS_PARAMS)); 
                }
                else {
                    // вернуть требуемый размер
                    return Marshal.SizeOf(typeof(API64.CK_RSA_PKCS_PSS_PARAMS));
                }
            }
            // закодировать параметры
            public object Encode(Module module, IntPtr ptr)
            {
                if (module.LongSize == 4)
                { 
                    API32.CK_RSA_PKCS_PSS_PARAMS parameters; 
                
                    // указать параметры
                    parameters.hashAlg = (uint)HashAlg; parameters.mgf = (uint)MGF;

                    // указать параметры
                    parameters.sLen = SaltLength; return parameters; 
                }
                else { 
                    API64.CK_RSA_PKCS_PSS_PARAMS parameters; 
                
                    // указать параметры
                    parameters.hashAlg = HashAlg; parameters.mgf = MGF;

                    // указать параметры
                    parameters.sLen = SaltLength; return parameters; 
                }
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Параметры алгоритмов DH
        ///////////////////////////////////////////////////////////////////////
        public class CK_X9_42_DH1_DERIVE_PARAMS : MechanismParameters 
        {
            // параметры алгоритма
            public readonly ulong KDF; public readonly byte[] OtherInfo; public readonly byte[] PublicData;

            // конструктор
	        public CK_X9_42_DH1_DERIVE_PARAMS(ulong kdf, byte[] otherInfo, byte[] publicData)
	        {
                // сохранить переданные параметры
		        KDF = kdf; OtherInfo = otherInfo; PublicData = publicData; 

                // проверить указание данных
                if (otherInfo  == null) OtherInfo  = new byte[0]; 
                if (publicData == null) PublicData = new byte[0]; 
	        }
            // определить требуемый размер буфера
            [SecuritySafeCritical]
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            public int GetBufferSize(Module module)
            {
                if (module.LongSize == 4)
                { 
                    // определить размер структуры
                    int total = Marshal.SizeOf(typeof(API32.CK_X9_42_DH1_DERIVE_PARAMS)); 
                    
                    // вернуть требуемый размер
                    return total + OtherInfo.Length + PublicData.Length; 
                }
                else {
                    // определить размер структуры
                    int total = Marshal.SizeOf(typeof(API64.CK_X9_42_DH1_DERIVE_PARAMS)); 
                    
                    // вернуть требуемый размер
                    return total + OtherInfo.Length + PublicData.Length; 
                }
            }
            // закодировать параметры
            [SecuritySafeCritical]
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            public object Encode(Module module, IntPtr ptr)
            {
                if (module.LongSize == 4)
                { 
                    API32.CK_X9_42_DH1_DERIVE_PARAMS parameters; parameters.kdf = (uint)KDF;

                    // инициализировать переменные
                    parameters.pOtherInfo = IntPtr.Zero; parameters.pPublicData = IntPtr.Zero; 
                        
                    // указать размер данных
                    parameters.ulOtherInfoLen  = OtherInfo .Length; 
                    parameters.ulPublicDataLen = PublicData.Length;

                    // определить адрес буфера
                    parameters.pOtherInfo = new IntPtr(ptr.ToInt64() + Marshal.SizeOf(parameters)); 

                    // скопировать данные
                    Marshal.Copy(OtherInfo, 0, parameters.pOtherInfo, OtherInfo.Length); 
                    
                    // определить адрес буфера
                    parameters.pPublicData = new IntPtr(parameters.pOtherInfo.ToInt64() + OtherInfo.Length); 

                    // скопировать salt-значение
                    Marshal.Copy(PublicData, 0, parameters.pPublicData, PublicData.Length); 
                    
                    // скорректировать значения указателей
                    if (OtherInfo .Length == 0) parameters.pOtherInfo  = IntPtr.Zero;
                    if (PublicData.Length == 0) parameters.pPublicData = IntPtr.Zero; return parameters; 
                }
                else { 
                    API64.CK_X9_42_DH1_DERIVE_PARAMS parameters; parameters.kdf = KDF;

                    // инициализировать переменные
                    parameters.pOtherInfo = IntPtr.Zero; parameters.pPublicData = IntPtr.Zero; 
                        
                    // указать размер данных
                    parameters.ulOtherInfoLen  = OtherInfo .Length; 
                    parameters.ulPublicDataLen = PublicData.Length;

                    // определить адрес буфера
                    parameters.pOtherInfo = new IntPtr(ptr.ToInt64() + Marshal.SizeOf(parameters)); 

                    // скопировать данные
                    Marshal.Copy(OtherInfo, 0, parameters.pOtherInfo, OtherInfo.Length); 
                    
                    // определить адрес буфера
                    parameters.pPublicData = new IntPtr(parameters.pOtherInfo.ToInt64() + OtherInfo.Length); 

                    // скопировать salt-значение
                    Marshal.Copy(PublicData, 0, parameters.pPublicData, PublicData.Length); 
                    
                    // скорректировать значения указателей
                    if (OtherInfo .Length == 0) parameters.pOtherInfo  = IntPtr.Zero;
                    if (PublicData.Length == 0) parameters.pPublicData = IntPtr.Zero; return parameters; 
                }
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Параметры алгоритмов ECDH
        ///////////////////////////////////////////////////////////////////////
        public class CK_ECDH1_DERIVE_PARAMS : MechanismParameters 
        {
            // параметры алгоритма
            public readonly ulong KDF; public readonly byte[] SharedData; public readonly byte[] PublicData;

            // конструктор
	        public CK_ECDH1_DERIVE_PARAMS(ulong kdf, byte[] sharedData, byte[] publicData)
	        {
                // сохранить переданные параметры
		        KDF = kdf; SharedData = sharedData; PublicData = publicData; 

                // проверить указание данных
                if (sharedData == null) SharedData = new byte[0]; 
                if (publicData == null) PublicData = new byte[0]; 
	        }
            // определить требуемый размер буфера
            [SecuritySafeCritical]
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            public int GetBufferSize(Module module)
            {
                if (module.LongSize == 4)
                { 
                    // определить размер структуры
                    int total = Marshal.SizeOf(typeof(API32.CK_ECDH1_DERIVE_PARAMS)); 
                    
                    // вернуть требуемый размер
                    return total + SharedData.Length + PublicData.Length; 
                }
                else {
                    // определить размер структуры
                    int total = Marshal.SizeOf(typeof(API64.CK_ECDH1_DERIVE_PARAMS)); 
                    
                    // вернуть требуемый размер
                    return total + SharedData.Length + PublicData.Length; 
                }
            }
            // закодировать параметры
            [SecuritySafeCritical]
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            public object Encode(Module module, IntPtr ptr)
            {
                if (module.LongSize == 4)
                { 
                    API32.CK_ECDH1_DERIVE_PARAMS parameters; parameters.kdf = (uint)KDF;

                    // инициализировать переменные
                    parameters.pSharedData = IntPtr.Zero; parameters.pPublicData = IntPtr.Zero; 
                        
                    // указать размер данных
                    parameters.ulSharedDataLen = SharedData.Length; 
                    parameters.ulPublicDataLen = PublicData.Length;

                    // определить адрес буфера
                    parameters.pSharedData = new IntPtr(ptr.ToInt64() + Marshal.SizeOf(parameters)); 

                    // скопировать данные
                    Marshal.Copy(SharedData, 0, parameters.pSharedData, SharedData.Length); 
                    
                    // определить адрес буфера
                    parameters.pPublicData = new IntPtr(parameters.pSharedData.ToInt64() + SharedData.Length); 

                    // скопировать salt-значение
                    Marshal.Copy(PublicData, 0, parameters.pPublicData, PublicData.Length); 
                    
                    // скорректировать значения указателей
                    if (SharedData.Length == 0) parameters.pSharedData = IntPtr.Zero;
                    if (PublicData.Length == 0) parameters.pPublicData = IntPtr.Zero; return parameters; 
                }
                else { 
                    API64.CK_ECDH1_DERIVE_PARAMS parameters; parameters.kdf = KDF;

                    // инициализировать переменные
                    parameters.pSharedData = IntPtr.Zero; parameters.pPublicData = IntPtr.Zero; 
                        
                    // указать размер данных
                    parameters.ulSharedDataLen = SharedData.Length; 
                    parameters.ulPublicDataLen = PublicData.Length;

                    // определить адрес буфера
                    parameters.pSharedData = new IntPtr(ptr.ToInt64() + Marshal.SizeOf(parameters)); 

                    // скопировать данные
                    Marshal.Copy(SharedData, 0, parameters.pSharedData, SharedData.Length); 
                    
                    // определить адрес буфера
                    parameters.pPublicData = new IntPtr(parameters.pSharedData.ToInt64() + SharedData.Length); 

                    // скопировать salt-значение
                    Marshal.Copy(PublicData, 0, parameters.pPublicData, PublicData.Length); 
                    
                    // скорректировать значения указателей
                    if (SharedData.Length == 0) parameters.pSharedData = IntPtr.Zero;
                    if (PublicData.Length == 0) parameters.pPublicData = IntPtr.Zero; return parameters; 
                }
            }
        }
    }
}
