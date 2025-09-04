# network_analyzer/database/operations.py

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from network_analyzer.database.models import Base

class DatabaseManager:
    """
    Handles DB connection, sessions, and setup
    """
    def __init__(self, db_url='sqlite:///network_analyzer.db'):
        self.engine = create_engine(db_url, echo=False)
        self.Session = sessionmaker(bind=self.engine)
        self._create_schema()

    def _create_schema(self):
        """Create tables"""
        Base.metadata.create_all(self.engine)

    def get_session(self):
        """Get a new session"""
        return self.Session()
