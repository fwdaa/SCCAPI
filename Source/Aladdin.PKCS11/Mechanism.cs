using System;
using System.Security;
using System.Security.Permissions;
using System.Runtime.InteropServices;

namespace Aladdin.PKCS11
{
    ///////////////////////////////////////////////////////////////////////////
    // Параметры алгоритма
    ///////////////////////////////////////////////////////////////////////////
    public class Mechanism
    {
        public readonly UInt64 AlgID;	    // идентификатор алгоритма 
        public readonly Object Parameters;  // параметры алгоритма

	    // конструктор
	    public Mechanism(ulong algID, Mechanism mechanism)
	    {
		    // инициализировать переменные
		    AlgID = algID; Parameters = mechanism.Parameters; 
	    }
	    // конструктор
	    public Mechanism(ulong algID)
	    {
		    // инициализировать переменные
		    AlgID = algID; Parameters = null; 
	    }
	    // конструктор
	    public Mechanism(ulong algID, byte[] value)
	    {
            // сохранить переданные параметры
		    AlgID = algID; Parameters = value;
	    }
	    public Mechanism(ulong algID, long value)
	    {
            // сохранить переданные параметры
		    AlgID = algID; Parameters = (ulong)value;
	    }
	    public Mechanism(ulong algID, MechanismParameters parameters)
        {
            // сохранить переданные параметры
            AlgID = algID; Parameters = parameters;
        }
        // закодировать параметры алгоритма
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public MechanismBuffer Encode(Module module)
        {
            // проверить наличие параметров
            if (Parameters == null) return new MechanismBuffer(); 

            // для байтовых данных
            if (Parameters is Byte[])
            {
                // выполнить преобразование типа 
                byte[] encoded = (byte[])Parameters; 

		        // выделить буфер требуемого размера
                IntPtr ptr = Marshal.AllocHGlobal(encoded.Length); 

                // скопировать данные
                Marshal.Copy(encoded, 0, ptr, encoded.Length); 

                // вернуть выделенный буфер
                return new MechanismBuffer(ptr, encoded.Length); 
            }
            // для числовых данных
            else if (Parameters is UInt64)
            {
                // закодировать параметры
                byte[] encoded = module.EncodeLong((UInt64)Parameters); 

		        // выделить буфер требуемого размера
                IntPtr ptr = Marshal.AllocHGlobal(encoded.Length); 

                // скопировать данные
                Marshal.Copy(encoded, 0, ptr, encoded.Length); 

                // вернуть выделенный буфер
                return new MechanismBuffer(ptr, encoded.Length); 
            }
            else { 
                // выполнить преобразование типа
                MechanismParameters parameters = (MechanismParameters)Parameters; 

                // определить требуемый размер буфера
                int total = parameters.GetBufferSize(module); 

		        // выделить буфер требуемого размера
		        IntPtr ptr = Marshal.AllocHGlobal(total); 

                // закодировать параметры
                object structure = parameters.Encode(module, ptr); 

                // скопировать параметры
                Marshal.StructureToPtr(structure, ptr, false);
            
                // указать размер структуры параметров
                int size = Marshal.SizeOf(structure); 

                // вернуть выделенный буфер
                return new MechanismBuffer(ptr, size); 
            }
        }
    }
}
