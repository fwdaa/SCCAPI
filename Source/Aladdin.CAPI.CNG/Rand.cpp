#include "stdafx.h"
#include "Rand.h"

void Aladdin::CSP::Rand::Generate(Binary^ buffer, int bufferOff, int bufferLen)
try{
	ATRACE_SCOPE(Aladdin::CSP::Rand::Generate); 

	// выделить вспомогательный буфер
	PBYTE pbBuffer = (PBYTE)_alloca(bufferLen);

	// сгенерировать данные в буфере
	AE_CHECK_WIN32_RESULT(::CryptGenRandom(hProvider, bufferLen, pbBuffer)); 

	// скопировать данные
	System::Runtime::InteropServices::Marshal::Copy(IntPtr(pbBuffer), buffer, bufferOff, bufferLen); 
}
// при ошибке выбросить исключение
catch(const CAException& e) { throw gcnew InteropException(e.Code()); }

