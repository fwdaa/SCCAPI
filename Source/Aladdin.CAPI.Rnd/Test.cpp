#include "stdafx.h"
#include "Test.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// Битовая последовательность
///////////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Rnd::Bits::Bits(array<BYTE>^ data, size_t n) : _bits(n), _ones(0)
{
	// указать маску выделения битов
	int mask = 0x1 << ((n % 8) ? (n % 8) - 1 : 7); 

	// для всех байтов
	for (size_t index = 0, i = 0; i < (n + 7) / 8; i++, mask = 0x80)
	{
		// для всех битов байта
		for (; mask != 0 && index < n; index++, mask >>= 1)
		{
			// извлечь требуемый бит
			_bits[index] = (data[(int)i] & mask) ? 1 : 0;

			// увеличить число единиц
			if (_bits[index]) _ones++; 
		}
	}
}

Aladdin::CAPI::Rnd::Bits::Bits(const void* data, size_t n) : _bits(n), _ones(0)
{
	// указать маску выделения битов
	int mask = 0x1 << ((n % 8) ? (n % 8) - 1 : 7); 

	// для всех байтов
	for (size_t index = 0, i = 0; i < (n + 7) / 8; i++, mask = 0x80)
	{
		// для всех битов байта
		for (; mask != 0 && index < n; index++, mask >>= 1)
		{
			// извлечь требуемый бит
			_bits[index] = (((unsigned char*)data)[i] & mask) ? 1 : 0;

			// увеличить число единиц
			if (_bits[index]) _ones++; 
		}
	}
}

size_t Aladdin::CAPI::Rnd::Bits::changes() const
{
	size_t count = 0; 

	// для всех битов
	for (size_t i = 1; i < _bits.size(); i++)
	{
		// увеличить число изменений 
		if (_bits[i] != _bits[i - 1]) count++; 
	}
	return count; 
}

size_t Aladdin::CAPI::Rnd::Bits::zeroes_seq() const
{
	size_t max_seq = 0; size_t seq = 0;

	// для всех битов
	for (size_t i = 0; i < _bits.size(); i++)
	{
		// увеличить размер серии
		if (!_bits[i]) seq++; 
		else { 
			// сохранить размер серии
			if (seq > max_seq) max_seq = seq;  
			
			// сбросить серию
			seq = 0; 
		}
	}
	// сохранить размер серии 
	if (seq > max_seq) { max_seq = seq; } return max_seq; 
}

size_t Aladdin::CAPI::Rnd::Bits::ones_seq() const
{
	size_t max_seq = 0; size_t seq = 0;

	// для всех битов
	for (size_t i = 0; i < _bits.size(); i++)
	{
		// увеличить размер серии
		if (_bits[i]) seq++; 
		else { 
			// сохранить размер серии
			if (seq > max_seq) max_seq = seq;  
			
			// сбросить серию
			seq = 0; 
		}
	}
	// сохранить размер серии
	if (seq > max_seq) { max_seq = seq; } return max_seq; 
}

bool Aladdin::CAPI::Rnd::Bits::check_ranges(size_t ones_min, size_t ones_max, 
	size_t changes_min, size_t changes_max, size_t max_seq_min, size_t max_seq_max) const
{
	// проверить число единиц
	if (_ones < ones_min || _ones >= ones_max) return false; size_t changes = 0;

	// указать начальные условия
	size_t max_zeroes_seq = 0; size_t zeroes_seq = 0;
	size_t max_ones_seq   = 0; size_t ones_seq   = 0;

	// для всех битов
	for (size_t i = 0; i < _bits.size(); i++)
	{
		// увеличить число изменений 
		if (i != 0 && _bits[i] != _bits[i - 1]) 
		{
			// проверить на максимальное число
			if (++changes >= changes_max) return false; 
		}
		// при наличии нуля
		if (!_bits[i]) 
		{ 
			// сохранить размер серии единиц
			if (ones_seq > max_ones_seq) max_ones_seq = ones_seq;  
			
			// сбросить серию единиц и продолжить серию нулей
			ones_seq = 0; zeroes_seq++; 

			// проверить на максимальное число
			if (zeroes_seq >= max_seq_max) return false; 
		}
		else { 
			// сохранить размер серии нулей
			if (zeroes_seq > max_zeroes_seq) max_zeroes_seq = zeroes_seq;  

			// сбросить серию нулей и продолжить серию единиц
			zeroes_seq = 0; ones_seq++; 

			// проверить на максимальное число
			if (ones_seq >= max_seq_max) return false; 
		}
	}
	// учесть размер последней серии
	if (zeroes_seq > max_zeroes_seq) { max_zeroes_seq = zeroes_seq; }
	if (ones_seq   > max_ones_seq  ) { max_ones_seq   = ones_seq  ; }

	// проверить минимальное значение
	if (changes < changes_min) return false; 
		
	// проверить минимальные значения
	return (max_zeroes_seq >= max_seq_min && max_ones_seq >= max_seq_min); 
}

///////////////////////////////////////////////////////////////////////////////
// Проверка корректности функционирования
///////////////////////////////////////////////////////////////////////////////
bool NonOverlapTest(const BitSequence* epsilon, size_t n, const BitSequence* mask, size_t m, size_t N); 

void Aladdin::CAPI::Rnd::Test::Run()
{
	// 2.1 Frequency (Monobit) Test 
	unsigned char epsilon1[] = { 0x2, 0xD5 }; FrequencyTest(epsilon1, 10); 

	// 2.2 Frequency Test within a Block
	unsigned char epsilon2[] = { 0x1, 0x9A }; FrequencyTest(epsilon2, 10, 3); 

	// 2.3 Runs Test
	unsigned char epsilon3[] = { 0x2, 0x6B }; RunsTest(epsilon3, 10); 

	// 2.7 Non-overlapping Template Matching Test
	unsigned char epsilon4[] = { 0xA, 0x4B, 0x96 }; unsigned char temp = 0x1; 
	
	// 2.7 Non-overlapping Template Matching Test
	Bits bits4(epsilon4, 20); Bits bitsTemp(&temp, 3);
	
	// 2.7 Non-overlapping Template Matching Test
	::NonOverlapTest(bits4.data(), 20, bitsTemp.data(), 3, 2); 

	// 2.11 Serial Test
	unsigned char epsilon5[] = { 0x0, 0xDD }; SerialTest(epsilon5, 10, 3); 

	// 2.12 Approximate Entropy Test 
	unsigned char epsilon6[] = { 0x1, 0x35 }; EntropyTest(epsilon6, 10, 3); 

	// 2.13 Cumulative Sums (Cusum) Test
	unsigned char epsilon7[] = { 0x2, 0xD7 }; CusumTest(epsilon7, 10, false); 
}
