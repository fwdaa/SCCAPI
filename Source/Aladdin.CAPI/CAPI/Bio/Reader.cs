using System; 

namespace Aladdin.CAPI.Bio
{
	///////////////////////////////////////////////////////////////////////////
	// Считыватель отпечатков пальца
	///////////////////////////////////////////////////////////////////////////
    public abstract class Reader : RefObject
    { 
        // имя считывателя
        public abstract string Name { get; } 

        // запустить процесс захвата отпечатка
        public abstract Remoting.RemoteClientControl BeginCapture(
            ImageTarget target, Predicate<Image> check, 
            TimeSpan timeout, Remoting.IBackgroundHandler handler
        ); 
    }
}
