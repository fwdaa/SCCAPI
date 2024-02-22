#include "stdafx.h"
#include "stsnist.h"
#include "cprob.h"  
#include <exception>
#include <vector>

////////////////////////////////////////////////////////////////////////////////////
// Вычислить статистику psi^2
////////////////////////////////////////////////////////////////////////////////////
static double psi2(const BitSequence* epsilon, size_t n, size_t m)
{
	// обработать частный случай
	if (m == 0 || m == -1) return 0.0; size_t mask = (size_t(1) << m) - 1; 

	// выделить память для частот
	std::vector<size_t> nu(mask + 1); size_t value = 0; double sum = 0; 

	// для всех скользящих окон (выполнить 2.11.4.2)
	for (size_t i = 0; i < n + m - 1; i++)
	{
		// определить значение m-вектора
		value = ((value << 1) ^ epsilon[i % n]) & mask; 

		// увеличить частоту
		if (i >= m - 1) nu[value]++; 
	}
	// для всех частот
	for (size_t i = 0; i < nu.size(); i++)
	{
		// сложить квадраты частот
		sum += (double)nu[i] * (double)nu[i]; 
	}
	// вычислить статистику 2.11.4.3
	return sum * pow(2.0, (double)m) / n - n; 
}

////////////////////////////////////////////////////////////////////////////////////
// 2.11 Serial Test
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-22r1a.pdf
////////////////////////////////////////////////////////////////////////////////////
bool SerialTest(const BitSequence* epsilon, size_t n, size_t m)
{
	// обработать частный случай 
	if (m == 1) return FrequencyTest(epsilon, n); 
	try { 
		// выполнить 2.11.4.3
		double psi2m0 = psi2(epsilon, n, m    );
		double psi2m1 = psi2(epsilon, n, m - 1);
		double psi2m2 = psi2(epsilon, n, m - 2);

		// выполнить 2.11.4.4
		double delta1 = psi2m0 - psi2m1;

		// выполнить 2.11.4.4
		double delta2 = psi2m0 - 2.0 * psi2m1 + psi2m2;

		// выполнить 2.11.4.5
		double p_value1 = igamc(pow(2.0, (double)(m - 2)), delta1 / 2.0);
		double p_value2 = igamc(pow(2.0, (double)(m - 3)), delta2 / 2.0);

		// выполнить 2.11.5
		return (p_value1 >= 0.01) && (p_value2 >= 0.01); 
	}
	// обработать возможную ошибку
	catch (const std::exception &) { return false; }
}

