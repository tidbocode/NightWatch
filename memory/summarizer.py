import ollama


class Summarizer:
    """Compresses old conversation turns into a running summary via the LLM."""

    def __init__(self, model: str):
        self.model = model

    def summarize(
        self,
        messages: list[dict],
        existing_summary: str | None = None,
    ) -> str:
        convo_text = "\n".join(
            f"{m['role'].capitalize()}: {m['content']}" for m in messages
        )

        if existing_summary:
            prompt = (
                f"Previous summary:\n{existing_summary}\n\n"
                f"New conversation to incorporate:\n{convo_text}\n\n"
                "Update the summary to include the new information. "
                "Be concise but preserve all important facts, names, preferences, "
                "and decisions. Write in third person. Output only the summary."
            )
        else:
            prompt = (
                f"Conversation:\n{convo_text}\n\n"
                "Summarize this conversation concisely. Preserve all important facts, "
                "names, preferences, and decisions. Write in third person. "
                "Output only the summary."
            )

        response = ollama.chat(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            options={"num_predict": 300},
        )
        return response.message.content.strip()
