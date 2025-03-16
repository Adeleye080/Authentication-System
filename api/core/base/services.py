from abc import ABC, abstractmethod


class Service(ABC):
    @abstractmethod
    def create(self, *args, **kwargs):
        pass

    @abstractmethod
    def fetch(self, **kwargs):
        pass

    @abstractmethod
    def fetch_all(self, **kwargs):
        pass

    @abstractmethod
    def update(self, **kwargs):
        pass

    @abstractmethod
    def delete(self, **kwargs):
        pass
