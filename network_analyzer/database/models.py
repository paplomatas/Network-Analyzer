# network_analyzer/database/models.py
from sqlalchemy import (
    Column, Integer, String, Float, DateTime, 
    ForeignKey, Text, Boolean, create_engine
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import datetime

Base = declarative_base()

class Packet(Base):
    """Model for storing individual packet information"""
    __tablename__ = 'packets'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    src_ip = Column(String(50))
    dst_ip = Column(String(50))
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(20))
    length = Column(Integer)
    ttl = Column(Integer, nullable=True)
    
    # Relationships
    http_data = relationship("HTTPData", back_populates="packet", uselist=False)
    dns_data = relationship("DNSData", back_populates="packet", uselist=False)
    tcp_data = relationship("TCPData", back_populates="packet", uselist=False)
    

class TrafficStat(Base):
    """Model for storing aggregated traffic statistics"""
    __tablename__ = 'traffic_stats'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    interval = Column(String(20))  # '1min', '5min', '1hour', etc.
    packets_count = Column(Integer)
    bytes_count = Column(Integer)
    unique_ips = Column(Integer)
    average_packet_size = Column(Float)


class ProtocolStat(Base):
    """Model for storing protocol distribution statistics"""
    __tablename__ = 'protocol_stats'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    protocol = Column(String(20))
    count = Column(Integer)
    bytes = Column(Integer)
    percentage = Column(Float)


class HTTPData(Base):
    """Model for storing HTTP specific data"""
    __tablename__ = 'http_data'
    
    id = Column(Integer, primary_key=True)
    packet_id = Column(Integer, ForeignKey('packets.id'))
    method = Column(String(10), nullable=True)
    host = Column(String(255), nullable=True)
    path = Column(String(1024), nullable=True)
    version = Column(String(10), nullable=True)
    status_code = Column(Integer, nullable=True)
    content_type = Column(String(100), nullable=True)
    content_length = Column(Integer, nullable=True)
    
    # Relationship
    packet = relationship("Packet", back_populates="http_data")


class DNSData(Base):
    """Model for storing DNS specific data"""
    __tablename__ = 'dns_data'
    
    id = Column(Integer, primary_key=True)
    packet_id = Column(Integer, ForeignKey('packets.id'))
    query_name = Column(String(255), nullable=True)
    query_type = Column(String(10), nullable=True)
    response_code = Column(Integer, nullable=True)
    is_response = Column(Boolean, default=False)
    answers = Column(Text, nullable=True)  # JSON-encoded list of answers
    
    # Relationship
    packet = relationship("Packet", back_populates="dns_data")


class TCPData(Base):
    """Model for storing TCP specific data"""
    __tablename__ = 'tcp_data'
    
    id = Column(Integer, primary_key=True)
    packet_id = Column(Integer, ForeignKey('packets.id'))
    seq_num = Column(Integer, nullable=True)
    ack_num = Column(Integer, nullable=True)
    flags = Column(String(20), nullable=True)  # E.g., 'SYN', 'ACK', 'FIN', etc.
    window_size = Column(Integer, nullable=True)
    
    # Relationship
    packet = relationship("Packet", back_populates="tcp_data")


class SecurityAlert(Base):
    """Model for storing security alerts"""
    __tablename__ = 'security_alerts'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    alert_type = Column(String(50))  # E.g., 'port_scan', 'dos_attempt', etc.
    severity = Column(Float)  # 0.0 to 1.0
    src_ip = Column(String(50), nullable=True)
    dst_ip = Column(String(50), nullable=True)
    description = Column(Text)
    raw_data = Column(Text, nullable=True)  # Additional context data in JSON


class AnomalyEvent(Base):
    """Model for storing detected anomalies"""
    __tablename__ = 'anomaly_events'
    
    id = Column(Integer, primary_key=True)
    start_time = Column(DateTime)
    end_time = Column(DateTime, nullable=True)
    anomaly_type = Column(String(50))  # E.g., 'traffic_spike', 'unusual_protocol', etc.
    confidence = Column(Float)  # 0.0 to 1.0
    affected_metric = Column(String(50))  # E.g., 'http_traffic', 'dns_queries', etc.
    description = Column(Text)
    is_resolved = Column(Boolean, default=False)