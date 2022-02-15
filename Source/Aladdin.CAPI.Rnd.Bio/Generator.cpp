#include "stdafx.h"
#include "Generator.h"
#include <math.h>
#include <vector>
#include <map>

using namespace Aladdin::CAPI::Rnd; 

///////////////////////////////////////////////////////////////////////////////
// Выполнить хэширование данных
///////////////////////////////////////////////////////////////////////////////
void HashData(const void* pvData, SIZE_T cbData, void* pBuffer); 

//////////////////////////////////////////////////////////////////////////
// Тесты NIST
//////////////////////////////////////////////////////////////////////////
inline bool NistTestRand32(BYTE* epsilon)
{
	// Frequency Test
	if (!Test::FrequencyTest(epsilon, 256)) return false; 

	// Block Frequency Test
	if (!Test::FrequencyTest(epsilon, 256, 128)) return false; 

	// Runs Test
	if (!Test::RunsTest(epsilon, 256)) return false; 

	// Non-overlapping Template Matching Test
	if (!Test::NonOverlapTest(epsilon, 256, 9)) return false; 

	// Serial Test
	if (!Test::SerialTest(epsilon, 256, 16)) return false; 

	// Cumulative Summ
	if (!Test::CusumTest(epsilon, 256)) return false; 

	// Approximate Entropy Test
	if (!Test::EntropyTest(epsilon, 256, 10)) return false; 

	return true; 
}

//////////////////////////////////////////////////////////////////////////
// Тест для испытательной лаборатории
//////////////////////////////////////////////////////////////////////////
inline bool CertTestRand32(const void* epsilon)
{
	// проверить параметры последовательности
	return Test::CheckRanges(epsilon, 256, 101, 156, 101, 155, 5, 25); 
}

//////////////////////////////////////////////////////////////////////////
// Подсчет значения энтропии по Шеннону
//////////////////////////////////////////////////////////////////////////
template <typename Container> 
double ShannonEntropy(const Container& values)
{
	// указать тип элемента
	typedef typename Container::value_type value_type; 

	// тип словаря
	typedef std::map<value_type, size_t> Dictionary; 

	// словарь встречаемости символов
	Dictionary umFreqs; double dLog2 = log(2.0);

	// для всех символов строки
	for (Container::const_iterator it = values.begin(); it != values.end(); ++it)
	{
		// найти символ в словаре
		Dictionary::iterator itFreqs = umFreqs.find(*it);

		// увеличить частоту символа
		if (itFreqs == umFreqs.end()) umFreqs[*it] = 1; else itFreqs->second++;
	}
	// проверить наличие 5 различных символов
	double dEntropy = 0; if (umFreqs.size() < 5) return dEntropy;

	// для всех символов из строки
	for (Dictionary::const_iterator it = umFreqs.begin(); it != umFreqs.end(); ++it)
	{
		// вычислить вероятность
		double p = (double)it->second / (double)values.size();

		// вычислить энтропию по Шеннону 
		dEntropy += p * log(p) / dLog2;
	}
	return -dEntropy;
}

//////////////////////////////////////////////////////////////////////////
// Подсчет значения энтропии для испытательной лаборатории
//////////////////////////////////////////////////////////////////////////
static double CertEntropy(const size_t (&v)[8], size_t count)
{
	// проверить наличие данных
	if (count == 0) return 0.0; double M = (double)count; 

	// установить начальные значение
	size_t v_min = SIZE_MAX; size_t v_max = 0; 

	// для всех позиций битов
	for (size_t i = 0; i < 8; i++)
	{
		// определить минимальное и максимальное значение
		if (v[i] < v_min) v_min = v[i]; 
		if (v[i] > v_max) v_max = v[i]; 
	}
	// вычислить P' = min(v_min / M, 1 - v_max / M)
	double P = (v_min < M - v_max) ? (v_min / M) : (1.0 - v_max / M);

	// вычислить P = P' - 1.96 / (4 * sqrt(2*M))
	P -= 1.96 / (4.0 * sqrt(2.0 * M)); if (P <= 0) return 0.0; 

	// вычислить 8 * (-P * log2(P) - (1-P) * log2(1-P))
	return 8.0 * (-P * log(P) / log(2.0) - (1.0 - P) * log(1.0 - P) / log(2.0)); 
}

//////////////////////////////////////////////////////////////////////////
// Генератор случайных данных
//////////////////////////////////////////////////////////////////////////
Generator::Generator()
{ 
	// адрес функции определения времени
	_pfnGetSystemTimeAsFileTime = (FARPROC)&::GetSystemTimeAsFileTime; 

	// получить адрес модуля
	if (HMODULE hModule = ::GetModuleHandleW(L"kernel32.dll"))
	{
		// получить адрес функции
		if (FARPROC pfn = ::GetProcAddress(hModule, "GetSystemTimePreciseAsFileTime"))
		{
			// сохранить адрес функции
			_pfnGetSystemTimeAsFileTime = pfn; 
		}
	}
} 

//////////////////////////////////////////////////////////////////////////
// Получить число микросекунд со времени 1.1.1970
//////////////////////////////////////////////////////////////////////////
#if _MSC_VER < 1700
long long Generator::GetMiсrosecondsSinceEpoch() const 
{
	// указать прототип функции
	typedef void (WINAPI* PFN_GET_SYSTEM_TIME_AS_FILE_TIME)(PFILETIME); 

	// получить число тиков с 1.1.1601
	FILETIME ft; (*(PFN_GET_SYSTEM_TIME_AS_FILE_TIME)_pfnGetSystemTimeAsFileTime)(&ft); 

	// определить число тиков с 1.1.1601
	ULONGLONG ticks = (((ULONGLONG)ft.dwHighDateTime) << 32) + ft.dwLowDateTime; 

	// определить число микросекунд с 1.1.1970
	return (LONGLONG)((ticks - 0x19DB1DED53E8000ui64) / 10); 
}
#else 
#include <chrono>
long long Generator::GetMiсrosecondsSinceEpoch() const 
{
	// указать тип времени
	typedef std::chrono::microseconds mсs_type; typedef mсs_type::rep rep_type;

	// получить текущее время
	std::chrono::system_clock::duration duration = 
		std::chrono::system_clock::now().time_since_epoch();

	// преобразовать текущее время в микросекунды
	return std::chrono::duration_cast<mсs_type>(duration).count();
}
#endif 

//////////////////////////////////////////////////////////////////////////
// Обработчик нажатий клавиш (режим совместимости)
//////////////////////////////////////////////////////////////////////////
size_t LegacyCharHandler::OnValidChar(long long timer, WCHAR ch, void* pBuffer)
{
	// сохранить параметры нажатия
	_occurences.push_back(timer); _str += ch; size_t M = _occurences.size(); 

	// вычислить энтропию
	double entropy = ShannonEntropy(_str); if (entropy * M < 256)
	{
		// вернуть процент готовности
		return (size_t)(entropy * M * 100 / 256); 
	}
	// прохэшировать данные
	HashData(&_occurences[0], M * sizeof(timer), pBuffer);

	// проверить выполнение тестов
	if (CertTestRand32(pBuffer)) return 100; _str.clear();

	// сбросить все принятые данные
	_occurences.clear(); _str.clear(); return 0;
}

size_t LegacyCharHandler::OnInvalidChar(WCHAR)
{
	// указать размер последовательности
	size_t M = _occurences.size();

	// вернуть процент готовности
	return (size_t)(ShannonEntropy(_str) * M * 100 / 256); 
}
 
//////////////////////////////////////////////////////////////////////////
// Обработчик нажатий клавиш (для сертификации)
//////////////////////////////////////////////////////////////////////////
size_t CertCharHandler::OnValidChar(long long timer, WCHAR, void* pBuffer)
{
	// определить частоты установленных битов
	if (timer & 0x01) _v[0]++; if (timer & 0x02) _v[1]++;
	if (timer & 0x04) _v[2]++; if (timer & 0x08) _v[3]++;
	if (timer & 0x10) _v[4]++; if (timer & 0x20) _v[5]++;
	if (timer & 0x40) _v[6]++; if (timer & 0x80) _v[7]++; 
	
	// сохранить параметры нажатия
	_occurences.push_back(timer); size_t M = _occurences.size(); 

	// вычислить энтропию
	double entropy = CertEntropy(_v, M); 
	
#ifdef CERT_TEST
	// выполнить запись тестовых данных
	wprintf(L"%lld -> %g\n", timer, entropy * M); 
#endif 
	// при недостаточности данных	
	if (entropy * M < 259)
	{
		// вернуть процент готовности
		return (size_t)(entropy * M * 100 / 259); 
	}
	// прохэшировать данные
	HashData(&_occurences[0], M * sizeof(timer), pBuffer);

	// проверить выполнение тестов
	if (CertTestRand32(pBuffer)) 
	{
#ifdef CERT_TEST
		// выполнить запись тестовых данных
		wprintf(L"\nHash = "); 

		// для всех байтов хэш-значения
		for (size_t i = 0; i < 32; i++)
		{
			// записать байт хэш-значения
			wprintf(L"%02X", ((PBYTE)pBuffer)[i]); 
		}
		wprintf(L"\n\n"); 
#endif 
		return 100; 
	}
	// сбросить все принятые данные
	_occurences.clear(); memset(_v, 0, sizeof(_v)); return 0;
}

size_t CertCharHandler::OnInvalidChar(WCHAR)
{
	// получить данные последнего нажатия
	if (_occurences.empty()) return 0; size_t M = _occurences.size() - 1;

	// удалить последнее нажатие
	long long last = _occurences.back(); _occurences.pop_back(); 

	// выполнить откат последнего нажатия
	if (last & 0x01) _v[0]--; if (last & 0x02) _v[1]--;
	if (last & 0x04) _v[2]--; if (last & 0x08) _v[3]--;
	if (last & 0x10) _v[4]--; if (last & 0x20) _v[5]--;
	if (last & 0x40) _v[6]--; if (last & 0x80) _v[7]--; 

	// вернуть процент готовности
	return (size_t)(CertEntropy(_v, M) * M * 100 / 259); 
}
