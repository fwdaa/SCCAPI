#pragma once

// Тип последовательности битов
typedef unsigned char BitSequence;

///////////////////////////////////////////////////////////////////////////////
// Тесты NIST
///////////////////////////////////////////////////////////////////////////////
bool FrequencyTest(const BitSequence* epsilon, size_t n);

// 2.2 Frequency Test within a Block
bool FrequencyTest(const BitSequence* epsilon, size_t n, size_t M);

// 2.3 Runs Test
bool RunsTest(const BitSequence* epsilon, size_t n);

// 2.7 Non-overlapping Template Matching Test
bool NonOverlapTest(const BitSequence* epsilon, size_t n, const BitSequence* mask, size_t m);
bool NonOverlapTest(const BitSequence* epsilon, size_t n, size_t m);

// 2.11 Serial Test
bool SerialTest(const BitSequence* epsilon, size_t n, size_t m);

// 2.12 Approximate Entropy Test 
bool EntropyTest(const BitSequence* epsilon, size_t n, size_t m);

// 2.13 Cumulative Sums (Cusum) Test
bool CusumTest(const BitSequence* epsilon, size_t n);
bool CusumTest(const BitSequence* epsilon, size_t n, bool mode);

