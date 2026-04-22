"""Domain exceptions."""


class DomainError(Exception):
    pass


class MessageError(DomainError):
    pass


class ConfigurationError(DomainError):
    pass
