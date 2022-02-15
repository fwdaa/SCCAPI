#pragma once
#include "stsnist.h"
#include <vector>

namespace Aladdin { namespace CAPI { namespace Rnd {

///////////////////////////////////////////////////////////////////////////////
// Битовая последовательность
///////////////////////////////////////////////////////////////////////////////
class Bits
{
	// конструктор
	public: Bits(array<BYTE>^ value, size_t n); 
	// конструктор
	public: Bits(const void* value, size_t n); 

	// последовательность битов
	public: const BitSequence* data() const { return &_bits[0]; }
	public:       BitSequence* data()       { return &_bits[0]; }
	// число битов
	public: size_t size() const { return _bits.size(); }

	// число нулей и единиц
	public: size_t zeroes() const { return size() - _ones; } 
	public: size_t ones  () const { return          _ones; } 

	// число изменений битов
	public: size_t changes() const; 

	// максимальное число нулей и единиц подряд
	public: size_t zeroes_seq() const; 
	public: size_t ones_seq  () const; 

	// проверить диапазон 
	public: bool check_ranges(
		size_t ones_min,	// минимальное число единиц (включительно)
		size_t ones_max,	// максимальное число единиц (не включительно)
		size_t changes_min,	// минимальное число изменений битов (включительно)
		size_t changes_max,	// максимальное число изменений битов (не включительно)
		size_t max_seq_min,	// минимальная последовательность неизменяемых битов (включительно)
		size_t max_seq_max	// максимальная последовательность неизменяемых битов (не включительно)
	) const;

	// набор битов
	private: std::vector<unsigned char> _bits; size_t _ones; 
};

///////////////////////////////////////////////////////////////////////////////
// Тесты NIST
///////////////////////////////////////////////////////////////////////////////
public ref class Test abstract sealed
{
// 2.1 Frequency (Monobit) Test 
public: static bool FrequencyTest(const Bits& bits)
{
	// выполнить тест
	return ::FrequencyTest(bits.data(), bits.size()); 
}
public: static bool FrequencyTest(array<BYTE>^ epsilon, int n)
{
	// выполнить тест
	Bits bits(epsilon, n); return ::FrequencyTest(bits.data(), n); 
}
public: static bool FrequencyTest(const void* epsilon, int n)
{
	// выполнить тест
	Bits bits(epsilon, n); return ::FrequencyTest(bits.data(), n); 
}

// 2.2 Frequency Test within a Block
public: static bool FrequencyTest(const Bits& bits, int M)
{
	// выполнить тест
	return ::FrequencyTest(bits.data(), bits.size(), M); 
}
public: static bool FrequencyTest(array<BYTE>^ epsilon, int n, int M)
{
	// выполнить тест
	Bits bits(epsilon, n); return ::FrequencyTest(bits.data(), n, M); 
}
public: static bool FrequencyTest(const void* epsilon, int n, int M)
{
	// выполнить тест
	Bits bits(epsilon, n); return ::FrequencyTest(bits.data(), n, M); 
}

// 2.3 Runs Test
public: static bool RunsTest(const Bits& bits)
{
	// выполнить тест
	return ::RunsTest(bits.data(), bits.size()); 
}
public: static bool RunsTest(array<BYTE>^ epsilon, int n)
{
	// выполнить тест
	Bits bits(epsilon, n); return ::RunsTest(bits.data(), n); 
}
public: static bool RunsTest(const void* epsilon, int n)
{
	// выполнить тест
	Bits bits(epsilon, n); return ::RunsTest(bits.data(), n); 
}

// 2.7 Non-overlapping Template Matching Test
public: static bool NonOverlapTest(const Bits& bits, const Bits& mask)
{
	// выполнить тест
	return ::NonOverlapTest(bits.data(), bits.size(), mask.data(), mask.size()); 
}
public: static bool NonOverlapTest(array<BYTE>^ epsilon, int n, array<BYTE>^ mask, int m)
{
	// извлечь биты
	Bits bits(epsilon, n); Bits bitsMask(mask, m);

	// выполнить тест
	return ::NonOverlapTest(bits.data(), n, bitsMask.data(), m); 
}
public: static bool NonOverlapTest(const void* epsilon, int n, const void* mask, int m)
{
	// извлечь биты
	Bits bits(epsilon, n); Bits bitsMask(mask, m);

	// выполнить тест
	return ::NonOverlapTest(bits.data(), n, bitsMask.data(), m); 
}
public: static bool NonOverlapTest(const Bits& bits, int m)
{
	// выполнить тест
	return ::NonOverlapTest(bits.data(), bits.size(), m); 
}
public: static bool NonOverlapTest(array<BYTE>^ epsilon, int n, int m)
{
	// выполнить тест
	Bits bits(epsilon, n); return ::NonOverlapTest(bits.data(), n, m); 
}
public: static bool NonOverlapTest(const void* epsilon, int n, int m)
{
	// выполнить тест
	Bits bits(epsilon, n); return ::NonOverlapTest(bits.data(), n, m); 
}

// 2.11 Serial Test
public: static bool SerialTest(const Bits& bits, int m)
{
	// выполнить тест
	return ::SerialTest(bits.data(), bits.size(), m); 
}
public: static bool SerialTest(array<BYTE>^ epsilon, int n, int m)
{
	// выполнить тест
	Bits bits(epsilon, n); return ::SerialTest(bits.data(), n, m); 
}
public: static bool SerialTest(const void* epsilon, int n, int m)
{
	// выполнить тест
	Bits bits(epsilon, n); return ::SerialTest(bits.data(), n, m); 
}

// 2.12 Approximate Entropy Test 
public: static bool EntropyTest(const Bits& bits, int m)
{
	// выполнить тест
	return ::EntropyTest(bits.data(), bits.size(), m); 
}
public: static bool EntropyTest(array<BYTE>^ epsilon, int n, int m)
{
	// выполнить тест
	Bits bits(epsilon, n); return ::EntropyTest(bits.data(), n, m); 
}
public: static bool EntropyTest(const void* epsilon, size_t n, int m)
{
	// выполнить тест
	Bits bits(epsilon, n); return ::EntropyTest(bits.data(), n, m); 
}

// 2.13 Cumulative Sums (Cusum) Test
public: static bool CusumTest(const Bits& bits, bool mode)
{
	// выполнить тест
	return ::CusumTest(bits.data(), bits.size(), mode); 
}
public: static bool CusumTest(const Bits& bits)
{
	// выполнить тест
	return ::CusumTest(bits.data(), bits.size()); 
}
public: static bool CusumTest(array<BYTE>^ epsilon, int n, bool mode)
{
	// выполнить тест
	Bits bits(epsilon, n); return ::CusumTest(bits.data(), n, mode); 
}
public: static bool CusumTest(array<BYTE>^ epsilon, int n)
{
	// выполнить тест
	Bits bits(epsilon, n); return ::CusumTest(bits.data(), n); 
}
public: static bool CusumTest(const void* epsilon, int n, bool mode)
{
	// выполнить тест
	Bits bits(epsilon, n); return ::CusumTest(bits.data(), n, mode); 
}
public: static bool CusumTest(const void* epsilon, int n)
{
	// выполнить тест
	Bits bits(epsilon, n); return ::CusumTest(bits.data(), n); 
}
// проверить диапазон 
public: static bool CheckRanges(const Bits& bits, 
	size_t ones_min, size_t ones_max, size_t changes_min,
	size_t changes_max, size_t seq_min, size_t seq_max)
{
	// проверить диапазон 
	return bits.check_ranges(ones_min, ones_max, 
		changes_min, changes_max, seq_min, seq_max
	); 
}
public: static bool CheckRanges(array<BYTE>^ epsilon, int n, 
	size_t ones_min, size_t ones_max, size_t changes_min,
	size_t changes_max, size_t seq_min, size_t seq_max)
{
	// извлечь биты и проверить диапазон 
	Bits bits(epsilon, n); return bits.check_ranges(
		ones_min, ones_max, changes_min, changes_max, seq_min, seq_max
	); 
}
public: static bool CheckRanges(const void* epsilon, int n, 
	size_t ones_min, size_t ones_max, size_t changes_min,
	size_t changes_max, size_t seq_min, size_t seq_max)
{
	// извлечь биты и проверить диапазон 
	Bits bits(epsilon, n); return bits.check_ranges(
		ones_min, ones_max, changes_min, changes_max, seq_min, seq_max
	); 
}

public: static void Run(); 
};
}}}

