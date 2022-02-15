using System;

namespace Aladdin.CAPI.Bio.BSAPI
{
	///////////////////////////////////////////////////////////////////////////
	// Провайдер биометрии
	///////////////////////////////////////////////////////////////////////////
    public abstract class Provider : CAPI.Bio.Provider
    {
        // конструктор
        public Provider() { API.Initiaize(); }
		// деструктор
		protected override void OnDispose() { API.Terminate(); base.OnDispose(); }

		// перечислить биометрические считыватели 
        public override string[] EnumerateReaders()
        {
            // перечислить биометрические считыватели
            return API.EnumerateDevices("usb"); 
        }
        // открыть объект считыватля
        public override Bio.Reader OpenReader(string name)
        {
            // открыть объект считыватля
            return new Reader(this, name); 
        }
		// создать изображение 
		public abstract Image CreateImage(byte[] bitmap); 
    }
}
