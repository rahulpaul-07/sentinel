"""
evaluate.py
-----------
Run Sentinel against every labeled target and report accuracy metrics.
Run from the project root:  python evaluate.py
"""

from sentinel.llm import LLMClient
from sentinel.evaluation import Metrics, evaluate_target

TARGETS = [
    "targets/vulnerable_app",
    "targets/safe_app",
]


def main() -> None:
    llm = LLMClient()
    total = Metrics()

    for target in TARGETS:
        print(f"Evaluating {target} ...")
        m = evaluate_target(llm, target)
        print(f"   TP={m.tp}  FP={m.fp}  FN={m.fn}")
        total = total + m

    print("\n==================  OVERALL  ==================")
    print(f"True Positives:  {total.tp}")
    print(f"False Positives: {total.fp}")
    print(f"False Negatives: {total.fn}")
    print(f"Precision: {total.precision:.0%}")
    print(f"Recall:    {total.recall:.0%}")
    print(f"F1 score:  {total.f1:.2f}")


if __name__ == "__main__":
    main()