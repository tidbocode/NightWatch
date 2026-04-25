from dataclasses import dataclass, field


@dataclass
class ConversationState:
    messages: list[dict] = field(default_factory=list)
    summary: str | None = None
    turn_count: int = 0

    def add(self, role: str, content: str) -> None:
        self.messages.append({"role": role, "content": content})
        if role == "user":
            self.turn_count += 1

    def pop_oldest(self, n: int) -> list[dict]:
        """Remove and return the n oldest messages for summarization."""
        removed = self.messages[:n]
        self.messages = self.messages[n:]
        return removed

    def set_summary(self, text: str) -> None:
        self.summary = text

    def clear(self) -> None:
        self.messages.clear()
        self.summary = None
        self.turn_count = 0
