"""Domain service implementation.

Implements Requirements:
- CORE-4: Domain-Based Message Consolidation - Domain operations
- CORE-5: Message Statistics Tracking - Domain statistics
"""

from collections import defaultdict

from ..models.message import EmailMessage
from ..models.statistics import GroupStatistics


class DomainService:
    """Service for domain operations.

    Implements:
    - CORE-4: Domain consolidation
    """

    def __init__(self):
        """Initialize domain service."""
        self._aliases = {
            # Amazon domains
            "store-news@amazon.com": "amazon.com",
            "amazon.com": "amazon.com",
            "emailinfo.amazon.com": "amazon.com",
            "marketplace.amazon.com": "amazon.com",
            "payments.amazon.com": "amazon.com",

            # PayPal domains
            "service@paypal.com": "paypal.com",
            "paypal.com": "paypal.com",
            "e.paypal.com": "paypal.com",
            "member.paypal.com": "paypal.com",

            # T-Mobile domains
            "t-mobile.com": "t-mobile.com",
            "notifications.t-mobile.com": "t-mobile.com",
            "donotreply@notifications.t-mobile.com": "t-mobile.com",
            "t-mobileusa.com": "t-mobile.com",

            # FreshBooks domains
            "mail@f02.freshbooks.com": "freshbooks.com",
            "freshbooks.com": "freshbooks.com",
            "notifications.freshbooks.com": "freshbooks.com",

            # Harbor Freight domains
            "harborfreight.com": "harborfreight.com",
            "no-reply@harborfreight.com": "harborfreight.com",
            "email.harborfreight.com": "harborfreight.com",

            # Email providers
            "email.apple.com": "apple.com",
            "email2.anthropic.com": "anthropic.com",
            "email.anthropic.com": "anthropic.com",

            # News/Media
            "news.bloomberg.com": "bloomberg.com",
            "message.bloomberg.com": "bloomberg.com",

            # E-commerce
            "emailinfo.bestbuy.com": "bestbuy.com",
            "em1.turbotax.intuit.com": "intuit.com",

            # Social/Tech
            "mail.beehiiv.com": "beehiiv.com",
            "notifications.huggingface.co": "huggingface.co",

            # Additional domains from screenshot
            "noreply@astound.com": "astound.com",
            "astound.com": "astound.com",
            "perplexity.ai": "perplexity.ai",
            "mail.perplexity.ai": "perplexity.ai",
            "ea.com": "ea.com",
            "email.ea.com": "ea.com",
            "playtesting@ea.com": "ea.com",
            "clicks.tech": "clicks.tech",
            "email.clicks.tech": "clicks.tech",
            "sixt.com": "sixt.com",
            "info@sixt.com": "sixt.com",
            "tweetdelete.net": "tweetdelete.net",
            "team@tweetdelete.net": "tweetdelete.net",
        }

    def normalize_domain(self, domain: str) -> str:
        """Normalize domain name.

        Implements:
        - DOM-2: Domain normalization
        """
        domain = domain.lower()

        # First try exact match
        if domain in self._aliases:
            return self._aliases[domain]

        # Then try to match email addresses
        if "@" in domain:
            _, domain_part = domain.split("@", 1)
            if domain_part in self._aliases:
                return self._aliases[domain_part]

        return domain

    def group_messages(self, messages: list[EmailMessage]) -> list[GroupStatistics]:
        """Group messages by domain, or by sender email for shared platforms.

        Implements:
        - CORE-4: Message grouping
        - CORE-5: Group statistics
        """
        # First pass: group by normalized domain
        domain_groups: dict[str, list[EmailMessage]] = defaultdict(list)
        for message in messages:
            normalized_domain = self.normalize_domain(message.sender.domain)
            domain_groups[normalized_domain].append(message)

        # For domains with multiple distinct sender emails (e.g. substack.com,
        # beehiiv.com), split into per-email groups so each newsletter is its
        # own row rather than being lumped together.
        groups = []
        for domain, msgs in domain_groups.items():
            distinct_names = {m.sender.display_name for m in msgs}
            # Split by email only when senders within the same domain use different
            # display names — that indicates distinct newsletters on a shared platform
            # (e.g. substack.com). Same display name across all emails means it's
            # one brand using multiple sending addresses (e.g. amazon.com) and
            # should stay as a single group.
            if len(distinct_names) > 1:
                email_groups: dict[str, list[EmailMessage]] = defaultdict(list)
                for m in msgs:
                    email_groups[m.sender.email].append(m)
                for email, email_msgs in email_groups.items():
                    groups.append(GroupStatistics.from_messages(email, email_msgs))
            else:
                groups.append(GroupStatistics.from_messages(domain, msgs))

        return sorted(groups, key=lambda g: (-g.statistics.total_count, g.domain))

