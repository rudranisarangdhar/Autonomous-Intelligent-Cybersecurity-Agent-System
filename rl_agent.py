# rl_agent.py
import json
import os
import random
import numpy as np
from typing import Tuple, Any, Dict, List

class RLAgent:
    """
    Simple tabular Q-learning agent for decision-making in your cyber agents system.
    - Q-table stored as dict: state_key -> list of q-values (one per action)
    - Actions are simple strings provided at init
    - Provides helpers to extract a compact discrete state from a DataFrame row
    """

    def __init__(self,
                 actions: List[str] = None,
                 alpha: float = 0.2,
                 gamma: float = 0.9,
                 epsilon: float = 0.15,
                 qfile: str = "q_table.json"):
        self.actions = actions or ["ignore", "log_only", "alert_admin", "block_ip", "increase_monitoring"]
        self.alpha = alpha
        self.gamma = gamma
        self.epsilon = epsilon
        self.qfile = qfile
        self.q = {}  # state_key -> list of q-values
        self.load()

    # -------------------------
    # Q-table utilities
    # -------------------------
    def _state_key(self, state: Tuple[Any, ...]) -> str:
        # state is a short tuple of integers/strings; serialize deterministically
        return "|".join(map(str, state))

    def ensure_state(self, key: str):
        if key not in self.q:
            self.q[key] = [0.0 for _ in self.actions]

    def choose_action(self, state: Tuple[Any, ...]) -> int:
        key = self._state_key(state)
        self.ensure_state(key)

        # epsilon-greedy
        if random.random() < self.epsilon:
            return random.randrange(len(self.actions))
        qvals = self.q[key]
        return int(np.argmax(qvals))

    def update(self, state: Tuple[Any, ...], action_idx: int, reward: float, next_state: Tuple[Any, ...]):
        key = self._state_key(state)
        next_key = self._state_key(next_state)
        self.ensure_state(key)
        self.ensure_state(next_key)

        predict = self.q[key][action_idx]
        target = reward + self.gamma * max(self.q[next_key])
        self.q[key][action_idx] += self.alpha * (target - predict)

    def save(self):
        try:
            with open(self.qfile, "w", encoding="utf-8") as f:
                json.dump(self.q, f)
        except Exception as e:
            print("RLAgent save error:", e)

    def load(self):
        if os.path.exists(self.qfile):
            try:
                with open(self.qfile, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                # JSON stores numbers as lists; convert str keys to list floats
                self.q = {k: [float(x) for x in v] for k, v in raw.items()}
            except Exception:
                self.q = {}

    # -------------------------
    # Domain helpers
    # -------------------------
    @staticmethod
    def severity_to_code(sev: str) -> int:
        # map severity text to small discrete codes
        if sev == "HIGH":
            return 2
        if sev == "MEDIUM":
            return 1
        if sev == "LOW":
            return 0
        return 0

    @staticmethod
    def prob_to_code(prob):
        # convert probability to coarse bucket
        try:
            p = float(prob)
        except Exception:
            return 0
        if p >= 0.85:
            return 3
        if p >= 0.6:
            return 2
        if p >= 0.4:
            return 1
        return 0

    def row_to_state(self, row: Dict) -> Tuple:
        """
        Extract compact discrete state from a row (dict-like).
        Use only a few features to keep the state-space small.
        State example: (pred, severity_code, prob_bucket)
        """
        pred = int(row.get("pred", 0))
        sev_code = self.severity_to_code(str(row.get("severity", "NONE")))
        prob_bucket = self.prob_to_code(row.get("prob", 0))
        return (pred, sev_code, prob_bucket)

    def reward_from_transition(self, row_before: Dict, action: str, row_after: Dict=None) -> float:
        """
        Basic reward function:
         - good: block ip when pred==1 and severity HIGH -> +10
         - good: alert_admin when pred==1 -> +5
         - prefer no false blocks: block when pred==0 -> -8
         - ignoring an attack -> -10
         - small negative for noisy/monitoring actions to prefer decisive actions
        You can expand this using labels, feedback, or later ground truth.
        """
        pred = int(row_before.get("pred", 0))
        severity = str(row_before.get("severity", "NONE"))
        base = 0.0

        if action == "block_ip":
            if pred == 1 and severity == "HIGH":
                base += 10.0
            elif pred == 1:
                base += 5.0
            else:
                base -= 8.0  # false positive block

        elif action == "alert_admin":
            if pred == 1:
                base += 5.0
            else:
                base -= 1.0

        elif action == "increase_monitoring":
            if pred == 1:
                base += 2.0
            else:
                base -= 0.5

        elif action == "log_only":
            base += 0.5 if pred == 1 else -0.1

        elif action == "ignore":
            base -= 10.0 if pred == 1 else 0.1

        # small penalty for 'noisy' low value actions to promote decisive ops
        return float(base)

    # -------------------------
    # Utility: human readable policy export
    # -------------------------
    def export_policy(self, filename="rl_policy.txt"):
        with open(filename, "w", encoding="utf-8") as f:
            for k, q in sorted(self.q.items()):
                best = int(np.argmax(q))
                f.write(f"{k} -> {self.actions[best]} (q={q})\n")

