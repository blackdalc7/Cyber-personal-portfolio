"""Chat integrations. Each provider posts an approval card and later updates it with the outcome."""

from .base import ChatError, ChatProvider, status_line
from .discord import DiscordChat
from .outbox import OutboxChat
from .slack import SlackChat

__all__ = ["ChatError", "ChatProvider", "DiscordChat", "OutboxChat", "SlackChat", "status_line"]
