"""Tests for Week 10 Tree of Thought Components"""
import pytest
from src.reasoning.branch_generator import BranchGenerator, Branch
from src.reasoning.branch_evaluator import BranchEvaluator


class TestBranchGenerator:
    def test_init(self):
        generator = BranchGenerator(num_branches=5)
        assert generator.num_branches == 5

    def test_generate_branches(self):
        generator = BranchGenerator(num_branches=5)
        risk = {'cve_id': 'CVE-2024-1234', 'cvss_score': 7.5}
        branches = generator.generate_branches(risk)
        assert len(branches) == 5
        assert all(isinstance(b, Branch) for b in branches)
        assert all(0 <= b.risk_score <= 10 for b in branches)


class TestBranchEvaluator:
    def test_init(self):
        evaluator = BranchEvaluator(quality_threshold=0.6)
        assert evaluator.quality_threshold == 0.6

    def test_evaluate_branch(self):
        evaluator = BranchEvaluator()
        branch = Branch(0, "conservative", "Conservative scoring", 6.5, 0.8, "Test")
        quality = evaluator.evaluate_branch(branch)
        assert 0 <= quality <= 1

    def test_prune_branches(self):
        evaluator = BranchEvaluator(quality_threshold=0.6)
        branches = [
            Branch(0, "strategy1", "Desc", 7.0, 0.7, "High quality"),
            Branch(1, "strategy2", "Desc", 5.0, 0.4, "Low quality"),
            Branch(2, "strategy3", "Desc", 8.0, 0.9, "High quality")
        ]
        pruned = evaluator.prune_branches(branches)
        assert len(pruned) <= len(branches)

    def test_select_best(self):
        evaluator = BranchEvaluator()
        branches = [
            Branch(0, "strategy1", "Desc", 6.0, 0.6, "Medium"),
            Branch(1, "strategy2", "Desc", 8.0, 0.9, "Best")
        ]
        best = evaluator.select_best(branches)
        assert best.branch_id == 1
