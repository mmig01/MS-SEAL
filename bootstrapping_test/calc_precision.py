import numpy as np
import pandas as pd
from math import log10, log2
from IPython.display import display

def compare_vector_pairs(vector_pairs):
    """
    Compare multiple pairs of vectors and return a summary DataFrame.
    """
    results = []
    for name, (a, b) in vector_pairs.items():
        error = np.abs(a - b)

        def precision_metrics(val, err):
            if err == 0:
                return float('inf'), float('inf')
            if val == 0:
                return 0.0, 0.0
            return -log2(err / abs(val)), -log10(err / abs(val))

        metrics = [precision_metrics(ai, ei) for ai, ei in zip(a, error)]
        bit_ps, dec_ps = zip(*metrics)
        avg_bit, avg_dec = np.mean(bit_ps), np.mean(dec_ps)
        max_i, min_i = np.argmax(error), np.argmin(error)

        results.append({
            "Pair Name": name,
            "Mean Error": np.mean(error),
            # "Max Error": error[max_i],
            # "Min Error": error[min_i],
            "Average Bit Precision": avg_bit,
            # "Max Bit Precision": bit_ps[max_i],
            # "Min Bit Precision": bit_ps[min_i],
            "Average Decimal Precision": avg_dec,
            # "Max Decimal Precision": dec_ps[max_i],
            # "Min Decimal Precision": dec_ps[min_i],
        })

    df = pd.DataFrame(results)
    return df