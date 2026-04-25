class TokenBudget:
    """
    Estimates token usage without a tokenizer library.
    Rule of thumb: 1 token ≈ 4 characters for English text.
    """

    def __init__(self, budget: int):
        self.budget = budget

    @staticmethod
    def estimate(text: str) -> int:
        return max(1, len(text) // 4)

    def messages_tokens(self, messages: list[dict]) -> int:
        # 4 extra tokens per message for role + formatting overhead
        return sum(self.estimate(m.get("content", "")) + 4 for m in messages)

    def used(self, messages: list[dict], summary: str | None = None) -> int:
        total = self.messages_tokens(messages)
        if summary:
            total += self.estimate(summary)
        return total

    def fraction_used(self, messages: list[dict], summary: str | None = None) -> float:
        return self.used(messages, summary) / self.budget

    def is_over_threshold(
        self,
        messages: list[dict],
        summary: str | None = None,
        threshold: float = 0.75,
    ) -> bool:
        return self.fraction_used(messages, summary) >= threshold
