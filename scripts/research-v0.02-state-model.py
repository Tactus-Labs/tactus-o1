#!/usr/bin/env python3
"""Finite design checks, NOT CKB/EVM/crypto tests or a production gate.

Only models accounting partitions, control consumption, bounded counters,
watch ages and sealed-prefix arithmetic. Authorization and receipt authenticity
are abstract preconditions. Run without dependencies from any directory.
"""
from dataclasses import dataclass, replace
from itertools import permutations, product
import json


class Rejected(Exception):
    pass


def require(condition):
    if not condition:
        raise Rejected()


def rejects(call):
    try:
        call()
    except Rejected:
        return
    raise AssertionError("invalid transition accepted")


@dataclass(frozen=True)
class Ledger:
    deposits: tuple
    credited_count: int
    balances: tuple
    burn: int
    released: int = 0
    frozen: bool = False
    refunds: frozenset = frozenset()
    escaped: frozenset = frozenset()

    def totals(self):
        p = sum(self.deposits)
        c = sum(self.deposits[:self.credited_count])
        f = sum(self.deposits[i] for i in self.refunds)
        e = sum(self.balances[i] for i in self.escaped)
        v = p - self.released - f - e
        return p, c, f, e, v

    def invariant(self):
        p, c, f, e, v = self.totals()
        assert 0 <= self.credited_count <= len(self.deposits)
        assert self.burn + sum(self.balances) == c
        assert 0 <= self.released <= self.burn
        assert all(self.credited_count <= i < len(self.deposits) for i in self.refunds)
        assert all(0 <= i < len(self.balances) for i in self.escaped)
        partitions = (p - c - f, c - self.burn - e, self.burn - self.released)
        assert min(partitions) >= 0
        assert v == sum(partitions)
        if not self.frozen:
            assert not self.refunds and not self.escaped

    def claim(self, kind, index=0, authorized=True):
        if kind == "release":
            require(self.burn > 0 and self.released == 0)
            result = replace(self, released=self.burn)
        elif kind == "refund":
            require(self.frozen and self.credited_count <= index < len(self.deposits))
            require(index not in self.refunds)
            result = replace(self, refunds=self.refunds | {index})
        elif kind == "escape":
            require(self.frozen and authorized and 0 <= index < len(self.balances))
            require(self.balances[index] > 0 and index not in self.escaped)
            result = replace(self, escaped=self.escaped | {index})
        else:
            raise ValueError(kind)
        result.invariant()
        return result


def accounting_checks():
    configurations = traces = transitions = 0
    for deposits in product(range(1, 4), repeat=2):
        for credited in range(3):
            c = sum(deposits[:credited])
            for burn in range(c + 1):
                for first_balance in range(c - burn + 1):
                    balances = (first_balance, c - burn - first_balance)
                    for already_released in ([0, burn] if burn else [0]):
                        initial = Ledger(deposits, credited, balances, burn, already_released)
                        initial.invariant()
                        rejects(lambda: initial.claim("refund", credited))
                        rejects(lambda: initial.claim("escape", 0))
                        state = replace(initial, frozen=True)
                        actions = []
                        if burn and not already_released:
                            actions.append(("release", 0))
                        actions.extend(("refund", i) for i in range(credited, 2))
                        actions.extend(("escape", i) for i, b in enumerate(balances) if b)
                        for i in range(credited):
                            rejects(lambda i=i: state.claim("refund", i))
                        for i, b in enumerate(balances):
                            if b:
                                rejects(lambda i=i: state.claim("escape", i, authorized=False))
                        configurations += 1
                        for order in permutations(actions):
                            current = state
                            for kind, index in order:
                                current = current.claim(kind, index)
                                transitions += 1
                                rejects(lambda: current.claim(kind, index))
                            assert current.totals()[-1] == 0
                            traces += 1
    return dict(configurations=configurations, claim_orders=traces, transitions=transitions)


@dataclass(frozen=True)
class Control:
    version: int = 0
    settled: int = 0
    born: int = 0
    frozen: bool = False

    def settle(self, expected, end, ordered, now):
        require(not self.frozen and expected == self.version)
        require(self.settled < end <= ordered)
        return Control(self.version + 1, end, now)

    def freeze(self, expected, watch_born, work_end, now, timeout):
        require(not self.frozen and expected == self.version)
        require(work_end > self.settled)
        require(now - self.born >= timeout and now - watch_born >= timeout)
        return replace(self, version=self.version + 1, frozen=True)


def control_checks():
    threshold = 3
    c = Control()
    frozen = c.freeze(0, 1, 2, 4, threshold)
    rejects(lambda: frozen.settle(0, 2, 2, 4))
    rejects(lambda: frozen.settle(frozen.version, 2, 2, 5))
    advanced = c.settle(0, 1, 2, 4)
    rejects(lambda: advanced.freeze(0, 1, 2, 4, threshold))
    rejects(lambda: advanced.freeze(advanced.version, 1, 2, 4, threshold))
    advanced.freeze(advanced.version, 1, 2, 7, threshold)
    rejects(lambda: advanced.freeze(advanced.version, 1, 1, 7, threshold))
    rejects(lambda: c.settle(0, 0, 2, 4))
    # Old idle Control plus newly admitted work must not allow instant freeze.
    rejects(lambda: c.freeze(0, 100, 1, 100, threshold))
    checks = 0
    for born, watch, now in product(range(5), repeat=3):
        if now < max(born, watch):
            continue
        c = Control(born=born)
        expected = now >= max(born, watch) + threshold
        try:
            c.freeze(0, watch, 1, now, threshold)
            assert expected
        except Rejected:
            assert not expected
        checks += 1
    return dict(age_combinations=checks, race_orders=2, targeted_rejections=7)


def backlog_checks():
    checks = 0
    for maximum in range(1, 5):
        for ordered in range(9):
            for settled in range(ordered + 1):
                if ordered - settled > maximum:
                    continue
                append_allowed = ordered + 1 - settled <= maximum
                if not append_allowed:
                    assert ordered > settled
                    # Progress is still possible at capacity; no append predicate
                    # is imposed on settlement or on a matured freeze.
                    c = Control(settled=settled)
                    progressed = c.settle(0, settled + 1, ordered, 1)
                    assert ordered + 1 - progressed.settled <= maximum
                    c.freeze(0, 0, ordered, 3, 3)
                checks += 1
    return dict(bounded_counter_states=checks)


def schedule_checks():
    combinations = 0
    for occupancy in product(range(9), repeat=4):
        queued = [(lane, depth) for depth in range(8) for lane in range(4)
                  if depth < occupancy[lane]]
        assert len(queued) == sum(occupancy)
        processed = []
        for batch in range(8):
            processed += queued[batch * 4:(batch + 1) * 4]
        assert processed == queued and len(set(processed)) == len(queued)
        for deposits in range(33):
            assert sum(min(4, max(0, deposits - b * 4)) for b in range(8)) == deposits
        combinations += 1
    # Each admitted forced transaction has its own <=250k cap. Earlier forced
    # slots cannot exhaust the maximum reservation of the remaining slots.
    for gases in product((0, 21_000, 250_000), repeat=4):
        for i, gas in enumerate(gases):
            assert sum(gases[:i]) + gas <= 1_000_000
    return dict(lane_occupancies=combinations, deposit_counts_per_occupancy=33,
                priority_gas_combinations=81)


def cursor_checks():
    # Lane IDs start at zero, deposit IDs start at one. Both settled cursors
    # are counts, so a shared raw `sequence > cursor` test loses lane message 0.
    combinations = 0
    for completed in range(5):
        for lane_sequence in range(5):
            processed = list(range(completed))
            assert (lane_sequence + 1 > completed) == (lane_sequence not in processed)
            deposit_sequence = lane_sequence + 1
            credited = list(range(1, completed + 1))
            assert (deposit_sequence > completed) == (deposit_sequence not in credited)
            combinations += 1
    assert not (0 > 0) and 0 + 1 > 0
    return dict(cursor_combinations=combinations, first_lane_message_regression=True)


def rejected_design_counterexamples():
    # Refund without a terminal boundary, then credit and burn the same deposit.
    p, refund, credited, burned = 10, 10, 10, 10
    assert p - refund < burned
    # Reopening after a balance escape lets the same frozen balance be spent.
    backing, escaped, later_burn = 10, 10, 10
    assert backing - escaped < later_burn
    # A heartbeat can postpone relative-age freeze indefinitely without settling.
    now, born, settled = 0, 0, 0
    for _ in range(10):
        now += 2
        born = now
        assert now - born < 3 and settled == 0
    # Shared remaining gas lets the first nominally mandatory tx crowd out the next.
    assert 1_000_000 - 1_000_000 < 21_000
    return ["refund_then_credit_double_liability", "resume_after_balance_escape",
            "heartbeat_without_settlement", "priority_gas_starvation"]


if __name__ == "__main__":
    print(json.dumps({
        "scope": "finite abstract design checks; no CKB, EVM, MPT, signatures or zk proofs",
        "accounting": accounting_checks(),
        "control": control_checks(),
        "backlog": backlog_checks(),
        "schedule": schedule_checks(),
        "cursors": cursor_checks(),
        "rejected_design_counterexamples": rejected_design_counterexamples(),
        "result": "PASS",
    }, indent=2))
