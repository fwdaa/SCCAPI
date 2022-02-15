using System;

namespace Aladdin.CAPI.Bio.BSAPI
{
	///////////////////////////////////////////////////////////////////////
	// Исключение библиотеки
	///////////////////////////////////////////////////////////////////////
    [Serializable]
	public class Exception : System.Exception
	{
		// конструктор
		public Exception(int code) : base(String.Empty) { HResult = code; }

        // код ошибки
        public int Code { get { return HResult; }}
	}
}
