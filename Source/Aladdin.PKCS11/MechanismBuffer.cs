using System;
using System.Security;
using System.Security.Permissions;
using System.Runtime.InteropServices;

namespace Aladdin.PKCS11
{
    ///////////////////////////////////////////////////////////////////////////
    // Закодированные параметры алгоритма
    ///////////////////////////////////////////////////////////////////////////
    public sealed class MechanismBuffer : Disposable
    {
	    public readonly IntPtr Ptr;	    // адрес буфера параметров
	    public readonly Int32  Size;	// размер параметров алгоритма

        // конструктор
        public MechanismBuffer() : this(IntPtr.Zero, 0) {}
        // конструктор
        public MechanismBuffer(IntPtr ptr, int size)
        {
            // сохранить переданные параметры
            Ptr = ptr; Size = size; 
        }
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        protected override void OnDispose() 
        { 
		    // освободить выделенную память
		    if (Ptr != IntPtr.Zero) Marshal.FreeHGlobal(Ptr); base.OnDispose(); 
        }
    }
}
