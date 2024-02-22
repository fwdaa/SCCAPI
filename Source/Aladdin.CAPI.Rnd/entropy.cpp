#include "stdafx.h"
#include "stsnist.h"
#include "cprob.h"  
#include <exception>
#include <vector>

////////////////////////////////////////////////////////////////////////////////////
// ¬ычислить статистику phi
////////////////////////////////////////////////////////////////////////////////////
static double phi(const BitSequence* epsilon, size_t n, size_t m)
{
	// обработать частный случай
	if (m == 0) return 0.0; size_t mask = (size_t(1) << m) - 1; 

	// выделить пам€ть дл€ частот
	std::vector<size_t> nu(mask + 1); size_t value = 0; double sum = 0; 

	// дл€ всех скольз€щих окон (выполнить 2.12.4.2)
	for (size_t i = 0; i < n + m - 1; i++)
	{
		// определить значение m-вектора
		value = ((value << 1) ^ epsilon[i % n]) & mask; 

		// увеличить частоту
		if (i >= m - 1) nu[value]++; 
	}
	// дл€ всех частот
	for (size_t i = 0; i < nu.size(); i++)
	{
		// проверить возможность логарифмировани€
		if (nu[i] == 0) continue; 

		// сложить взвешенные логарифмы
		sum += (double)nu[i] * log((double)nu[i] / n); 
	}
	// вычислить статистику 2.12.4.3
	return sum / n; 
}

////////////////////////////////////////////////////////////////////////////////////
// 2.12 Approximate Entropy Test 
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-22r1a.pdf
////////////////////////////////////////////////////////////////////////////////////
bool EntropyTest(const BitSequence* epsilon, size_t n, size_t m)
{
	try { 
		// выполнить 2.12.4.3
		double phim0 = phi(epsilon, n, m    );
		double phim1 = phi(epsilon, n, m + 1);

		// выполнить 2.12.4.4
		double chi2 = 2.0 * n * (log(2.0) - (phim0 - phim1));

		// выполнить 2.12.4.5
		double p_value = igamc(pow(2.0, (double)(m - 1)), chi2 / 2);
	
		// выполнить 2.12.5
		return (p_value >= 0.01); 
	}
	// обработать возможную ошибку
	catch (const std::exception &) { return false; }
}