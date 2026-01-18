from dataclasses import dataclass


@dataclass
class EmailPayload:
    subject: str
    from_email: str
    to: list[str]
    text: str | None = None
    html: str | None = None

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "from_email": self.from_email,
            "to": self.to,
            "text": self.text,
            "html": self.html,
        }
