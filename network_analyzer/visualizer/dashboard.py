from flask import Flask, jsonify, request
from dash import Dash, dcc, dash_table, html, Input, Output, State
import dash_bootstrap_components as dbc
import dash
import plotly.graph_objs as go
import pandas as pd
import numpy as np
import os
import time
import logging
import tempfile
from datetime import datetime
from dotenv import load_dotenv
from network_analyzer.utils.helpers import load_config

# Set up logging
logger = logging.getLogger(__name__)

# Load environment variables and configuration
load_dotenv()
API_KEY = os.getenv("API_KEY", "changeme")
CONFIG = load_config()
THEME = CONFIG['dashboard'].get('theme', 'bootstrap')

class NetworkDashboard:
    def __init__(self, traffic_analyzer, protocol_stats, security_analyzer, anomaly_detector, flow_analyzer=None):
        self.traffic_analyzer = traffic_analyzer
        self.protocol_stats = protocol_stats
        self.security_analyzer = security_analyzer
        self.anomaly_detector = anomaly_detector
        self.flow_analyzer = flow_analyzer  # Add flow analyzer
        self.last_update = time.time()

        self.server = Flask(__name__)
        self.app = Dash(
            __name__, 
            server=self.server, 
            external_stylesheets=[
                dbc.themes.BOOTSTRAP,
                # Add Font Awesome for better icons
                "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css"
            ]
        )
        
        # Set title
        self.app.title = "Network Traffic Analyzer"
        
        self.setup_layout()
        self.setup_callbacks()
        self.setup_api_routes()


    def create_packet_list_view():
        return html.Div([
            html.Div([
                dcc.Input(id='packet-filter', type='text', placeholder='Filter...', className='mr-2'),
                html.Button('Apply Filter', id='apply-filter', className='btn btn-primary'),
            ], className='mb-2'),
            
            html.Div(id='packet-list-container', className='overflow-auto', style={'height': '400px'}, children=[
                dash_table.DataTable(
                    id='packet-table',
                    columns=[
                        {'name': 'No.', 'id': 'id'},
                        {'name': 'Time', 'id': 'time'},
                        {'name': 'Source', 'id': 'source'},
                        {'name': 'Destination', 'id': 'destination'},
                        {'name': 'Protocol', 'id': 'protocol'},
                        {'name': 'Length', 'id': 'length'},
                        {'name': 'Info', 'id': 'info'},
                    ],
                    data=[],
                    style_table={'overflowX': 'auto'},
                    style_cell={
                        'textOverflow': 'ellipsis',
                        'overflow': 'hidden',
                        'maxWidth': 0,
                    },
                    style_data_conditional=[
                        {
                            'if': {'row_index': 'odd'},
                            'backgroundColor': 'rgb(248, 248, 248)'
                        },
                        {
                            'if': {'filter_query': '{protocol} = "HTTP"'},
                            'backgroundColor': '#d6ffd6',
                        },
                        {
                            'if': {'filter_query': '{protocol} = "DNS"'},
                            'backgroundColor': '#ecf3ff',
                        },
                        {
                            'if': {'filter_query': '{protocol} = "TCP"'},
                            'backgroundColor': '#fff7e5',
                        },
                    ],
                    page_size=50,
                    sort_action='native',
                    filter_action='native',
                    row_selectable='single'
                )
            ])
        ])

    def setup_layout(self):
        self.app.layout = html.Div(className="container-fluid", children=[
            html.Div(className="row bg-primary text-white p-3 mb-3", children=[
                html.Div(className="col", children=[
                    html.H1("Network Traffic Analyzer", className="text-center"),
                    html.Div(id="connection-status", className="text-center")
                ])
            ]),

            html.Div(className="row gx-3", children=[
                html.Div(className="col-lg-4 col-md-12", children=[
                    html.Div(className="card mb-3", children=[
                        html.Div(className="card-header bg-info text-white", children=[
                            html.H4("Live Traffic", className="mb-0"),
                        ]),
                        html.Div(className="card-body", children=[
                            dcc.Graph(id='live-traffic-graph', style={"height": "280px"}),
                        ])
                    ]),
                ]),

                html.Div(className="col-lg-4 col-md-6", children=[
                    html.Div(className="card mb-3", children=[
                        html.Div(className="card-header bg-info text-white", children=[
                            html.H4("Protocol Distribution", className="mb-0"),
                        ]),
                        html.Div(className="card-body", children=[
                            dcc.Graph(id='protocol-pie-chart', style={"height": "280px"}),
                        ])
                    ]),
                ]),

                html.Div(className="col-lg-4 col-md-6", children=[
                    html.Div(className="card mb-3", children=[
                        html.Div(className="card-header bg-info text-white", children=[
                            html.H4("Top Source IPs", className="mb-0"),
                        ]),
                        html.Div(className="card-body", children=[
                            dcc.Graph(id='source-bar-chart', style={"height": "280px"})
                        ])
                    ]),
                ])
            ]),

            html.Div(className="row gx-3", children=[
                html.Div(className="col-lg-6 col-md-6", children=[
                    html.Div(className="card mb-3", children=[
                        html.Div(className="card-header bg-info text-white", children=[
                            html.H4("Top Destination IPs", className="mb-0"),
                        ]),
                        html.Div(className="card-body", children=[
                            dcc.Graph(id='destination-bar-chart', style={"height": "280px"})
                        ])
                    ]),
                ]),

                html.Div(className="col-lg-6 col-md-6", children=[
                    html.Div(className="card mb-3", children=[
                        html.Div(className="card-header bg-info text-white", children=[
                            html.H4("Security Alerts", className="mb-0"),
                        ]),
                        html.Div(className="card-body", style={"height": "320px", "overflowY": "auto"}, children=[
                            html.Div(id="alerts-table", className="table-responsive")
                        ])
                    ]),
                ])
            ]),

            html.Div(className="row gx-3", children=[
                html.Div(className="col-lg-6 col-md-6", children=[
                    html.Div(className="card mb-3", children=[
                        html.Div(className="card-header bg-info text-white", children=[
                            html.H4("Bandwidth Over Time", className="mb-0"),
                        ]),
                        html.Div(className="card-body", children=[
                            dcc.Graph(id='bandwidth-line-chart')
                        ])
                    ]),
                ]),
                html.Div(className="col-lg-6 col-md-6", children=[
                    html.Div(className="card mb-3", children=[
                        html.Div(className="card-header bg-info text-white", children=[
                            html.H4("Top Ports", className="mb-0"),
                        ]),
                        html.Div(className="card-body", children=[
                            dcc.Graph(id='top-ports-chart')
                        ])
                    ]),
                ])
            ]),

            # Add Flow Analysis section
            html.Div(className="row gx-3 mt-4", children=[
                html.Div(className="col-12", children=[
                    html.Div(className="card mb-3", children=[
                        html.Div(className="card-header bg-info text-white", children=[
                            html.H3("Flow Analysis", className="mb-0"),
                        ]),
                        html.Div(className="card-body", children=[
                            dcc.Tabs([
                                dcc.Tab(label="Active Flows", children=[
                                    html.Div(id="active-flows-table", className="border rounded p-2 mt-2", 
                                            style={"height": "400px", "overflowY": "auto"}),
                                    html.Div(className="d-flex align-items-center mt-2", children=[
                                        html.Div(id='selected-flow-info', className='me-2'),
                                        dcc.Dropdown(
                                            id='flow-context-menu',
                                            options=[
                                                {'label': 'Export as PCAP', 'value': 'export_pcap'},
                                                {'label': 'View Details', 'value': 'view_details'},
                                                {'label': 'Flag as Suspicious', 'value': 'flag_suspicious'}
                                            ],
                                            placeholder='Flow Actions...',
                                            className='mt-2'
                                        )
                                    ])
                                ]),
                                dcc.Tab(label="Flow Statistics", children=[
                                    html.Div(className="row mt-2", children=[
                                        html.Div(className="col-md-6", children=[
                                            dcc.Graph(id='flow-types-chart')
                                        ]),
                                        html.Div(className="col-md-6", children=[
                                            dcc.Graph(id='flow-duration-chart')
                                        ])
                                    ])
                                ]),
                                dcc.Tab(label="Flow Network", children=[
                                    dcc.Graph(id='flow-network-graph', style={"height": "600px"})
                                ])
                            ])
                        ])
                    ])
                ]),
            ]),

            # Hidden divs for interval updates
            dcc.Interval(id='fast-interval', interval=1000, n_intervals=0),    # 1 second
            dcc.Interval(id='medium-interval', interval=5000, n_intervals=0),  # 5 seconds
            dcc.Interval(id='slow-interval', interval=15000, n_intervals=0),   # 15 seconds
            dcc.Interval(id='flow-update', interval=5000, n_intervals=0),      # 5 seconds for flow updates
            
            # Store the timestamp of the last data update
            dcc.Store(id='last-update-time', data=time.time()),
            
            # Download component for PCAP exports
            dcc.Download(id='download-pcap'),
        ])

    def setup_callbacks(self):
        # Connection status callback
        @self.app.callback(
            Output('connection-status', 'children'),
            [Input('fast-interval', 'n_intervals')]
        )
        def update_connection_status(_):
            packet_count = sum(self.traffic_analyzer.protocol_counts.values())
            elapsed = time.time() - self.traffic_analyzer.start_time if hasattr(self.traffic_analyzer, 'start_time') else 0
            
            if elapsed > 0:
                rate = packet_count / elapsed
                status = html.Div([
                    html.Span(f"Status: ", className="me-2"),
                    html.Span(
                        "Active" if packet_count > 0 else "Waiting for traffic...", 
                        className=f"badge {'bg-success' if packet_count > 0 else 'bg-warning'} me-3"
                    ),
                    html.Span(f"Packets captured: {packet_count}", className="me-3"),
                    html.Span(f"Rate: {rate:.2f} packets/sec", className="me-3"),
                    html.Span(f"Running time: {int(elapsed)} seconds", className="me-3"),
                ])
                return status
            else:
                return html.Div([
                    html.Span("Status: ", className="me-2"),
                    html.Span("Initializing...", className="badge bg-warning")
                ])

        @self.app.callback(
            Output('live-traffic-graph', 'figure'),
            [Input('fast-interval', 'n_intervals')]
        )
        def update_traffic(_):
            try:
                traffic = self.traffic_analyzer.get_traffic_over_time()
                
                # Safety check
                times = traffic.get('times', [])
                counts = traffic.get('counts', [])

                if not times or not counts:
                    # Create empty chart with placeholders
                    current_time = time.time()
                    return {
                        'data': [
                            go.Scatter(
                                x=[current_time - 120, current_time - 60, current_time], 
                                y=[0, 0, 0], 
                                mode='lines', 
                                name='Packets',
                                line=dict(color='#2E86C1', width=3)
                            )
                        ],
                        'layout': go.Layout(
                            title='Waiting for network traffic...',
                            xaxis={'title': 'Time', 'type': 'date'},
                            yaxis={'title': 'Packets'},
                            margin=dict(l=40, r=20, t=40, b=40),
                            hovermode='closest',
                            plot_bgcolor='#F8F9F9',
                            paper_bgcolor='#F8F9F9'
                        )
                    }

                # Convert Unix timestamps to datetime for better labels
                time_labels = [pd.to_datetime(t, unit='s') for t in times]
                
                return {
                    'data': [
                        go.Scatter(
                            x=time_labels, 
                            y=counts, 
                            mode='lines', 
                            name='Packets',
                            line=dict(color='#2E86C1', width=3)
                        )
                    ],
                    'layout': go.Layout(
                        title='Network Traffic Over Time',
                        xaxis={'title': 'Time', 'type': 'date'},
                        yaxis={'title': 'Packets'},
                        margin=dict(l=40, r=20, t=40, b=40),
                        hovermode='closest',
                        plot_bgcolor='#F8F9F9',
                        paper_bgcolor='#F8F9F9'
                    )
                }

            except Exception as e:
                logger.error(f"Traffic callback error: {e}")
                # Return empty chart on error
                current_time = time.time()
                return {
                    'data': [
                        go.Scatter(
                            x=[current_time - 120, current_time - 60, current_time], 
                            y=[0, 0, 0], 
                            mode='lines', 
                            name='Packets'
                        )
                    ],
                    'layout': go.Layout(
                        title='Error loading traffic data',
                        xaxis={'title': 'Time'},
                        yaxis={'title': 'Packets'}
                    )
                }

        @self.app.callback(
            Output('protocol-pie-chart', 'figure'),
            [Input('medium-interval', 'n_intervals')]
        )

        def update_protocol(_):
            try:
                dist = self.traffic_analyzer.get_protocol_distribution()
                
                if not dist:
                    # Return empty pie chart
                    return {
                        'data': [go.Pie(labels=['No Data'], values=[1], hole=0.4)],
                        'layout': go.Layout(
                            title='Waiting for protocol data...',
                            margin=dict(l=20, r=20, t=40, b=20),
                            plot_bgcolor='#F8F9F9',
                            paper_bgcolor='#F8F9F9'
                        )
                    }
                    
                labels = list(dist.keys())
                values = [val[0] for val in dist.values()]
                
                return {
                    'data': [
                        go.Pie(
                            labels=labels, 
                            values=values, 
                            hole=0.4,
                            marker=dict(
                                colors=[
                                    '#3498DB', '#2ECC71', '#F1C40F', '#E74C3C', 
                                    '#9B59B6', '#1ABC9C', '#F39C12', '#D35400'
                                ]
                            ),
                            textinfo='label+percent',
                            hoverinfo='label+value+percent',
                            textposition='outside'
                        )
                    ],
                    'layout': go.Layout(
                        title='Protocol Distribution',
                        margin=dict(l=20, r=20, t=40, b=20),
                        plot_bgcolor='#F8F9F9',
                        paper_bgcolor='#F8F9F9',
                        showlegend=False
                    )
                }
            except Exception as e:
                logger.error(f"Protocol chart error: {e}")
                return {
                    'data': [go.Pie(labels=['Error'], values=[1])],
                    'layout': go.Layout(title='Error loading protocol data')
                }

        @self.app.callback(
            Output('source-bar-chart', 'figure'),
            [Input('medium-interval', 'n_intervals')]
        )
        def update_sources(_):
            try:
                sources = self.traffic_analyzer.get_top_talkers()['sources']
                
                if not sources:
                    return {
                        'data': [],
                        'layout': go.Layout(
                            title='Waiting for source IP data...',
                            xaxis={'title': 'Count'},
                            yaxis={'title': 'IP Address'},
                            margin=dict(l=60, r=20, t=40, b=40),
                            plot_bgcolor='#F8F9F9',
                            paper_bgcolor='#F8F9F9'
                        )
                    }
                    
                # Sort by count, descending
                ips = list(sources.keys())
                counts = list(sources.values())
                
                data = sorted(zip(ips, counts), key=lambda x: x[1], reverse=True)
                ips = [ip for ip, _ in data]
                counts = [count for _, count in data]
                
                return {
                    'data': [
                        go.Bar(
                            x=counts,
                            y=ips,
                            orientation='h',
                            marker=dict(color='#3498DB')
                        )
                    ],
                    'layout': go.Layout(
                        title='Top Source IPs',
                        xaxis={'title': 'Packets'},
                        yaxis={'title': 'IP Address'},
                        margin=dict(l=140, r=20, t=40, b=40),
                        plot_bgcolor='#F8F9F9',
                        paper_bgcolor='#F8F9F9'
                    )
                }
            except Exception as e:
                logger.error(f"Source chart error: {e}")
                return {
                    'data': [],
                    'layout': go.Layout(title='Error loading source data')
                }

        @self.app.callback(
            Output('destination-bar-chart', 'figure'),
            [Input('medium-interval', 'n_intervals')]
        )
        def update_destinations(_):
            try:
                destinations = self.traffic_analyzer.get_top_talkers()['destinations']
                
                if not destinations:
                    return {
                        'data': [],
                        'layout': go.Layout(
                            title='Waiting for destination IP data...',
                            xaxis={'title': 'Count'},
                            yaxis={'title': 'IP Address'},
                            margin=dict(l=60, r=20, t=40, b=40),
                            plot_bgcolor='#F8F9F9',
                            paper_bgcolor='#F8F9F9'
                        )
                    }
                
                # Sort by count, descending
                ips = list(destinations.keys())
                counts = list(destinations.values())
                
                data = sorted(zip(ips, counts), key=lambda x: x[1], reverse=True)
                ips = [ip for ip, _ in data]
                counts = [count for _, count in data]
                
                return {
                    'data': [
                        go.Bar(
                            x=counts,
                            y=ips,
                            orientation='h',
                            marker=dict(color='#2ECC71')
                        )
                    ],
                    'layout': go.Layout(
                        title='Top Destination IPs',
                        xaxis={'title': 'Packets'},
                        yaxis={'title': 'IP Address'},
                        margin=dict(l=140, r=20, t=40, b=40),
                        plot_bgcolor='#F8F9F9',
                        paper_bgcolor='#F8F9F9'
                    )
                }
            except Exception as e:
                logger.error(f"Destination chart error: {e}")
                return {
                    'data': [],
                    'layout': go.Layout(title='Error loading destination data')
                }

        @self.app.callback(
            Output('alerts-table', 'children'),
            [Input('medium-interval', 'n_intervals')]
        )
        def update_alerts(_):
            try:
                alerts = self.security_analyzer.get_recent_alerts(10)
                
                if not alerts:
                    return html.Div([
                        html.P("No security alerts detected.", className="text-muted text-center my-4"),
                        html.I(className="fas fa-shield-alt fa-3x text-muted d-block text-center")
                    ])
                
                rows = []
                for alert in alerts:
                    try:
                        # Convert any timestamp format to float first
                        timestamp_float = float(alert['timestamp'])
                        timestamp = pd.to_datetime(timestamp_float, unit='s').strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        # Fallback for any timestamp conversion issues
                        timestamp = str(alert['timestamp'])
                    
                    # Determine severity class
                    if alert.get('severity', 0) > 7:
                        severity_class = "bg-danger text-white"
                    elif alert.get('severity', 0) > 5:
                        severity_class = "bg-warning"
                    else:
                        severity_class = "bg-info text-white"
                    
                    rows.append(html.Tr([
                        html.Td(timestamp),
                        html.Td(alert.get('type', 'Unknown')),
                        html.Td(alert.get('details', '')),
                        html.Td(
                            str(alert.get('severity', 'N/A')), 
                            className=severity_class
                        )
                    ]))
                
                table = html.Table([
                    html.Thead(html.Tr([
                        html.Th("Time"), 
                        html.Th("Type"), 
                        html.Th("Details"), 
                        html.Th("Severity")
                    ]), className="table-dark"),
                    html.Tbody(rows)
                ], className="table table-striped table-hover")
                
                return table
            
            except Exception as e:
                logger.error(f"Alerts table error: {e}")
                return html.Div("Error loading security alerts")

        @self.app.callback(
            Output('bandwidth-line-chart', 'figure'),
            [Input('slow-interval', 'n_intervals')]
        )
        def update_bandwidth_chart(_):
            try:
                stats = self.protocol_stats.get_protocol_bandwidth(normalize=True)
                
                if not stats:
                    return {
                        'data': [],
                        'layout': go.Layout(
                            title='Waiting for bandwidth data...',
                            xaxis={'title': 'Protocol'},
                            yaxis={'title': 'Bytes/sec'},
                            margin=dict(l=40, r=20, t=40, b=40),
                            plot_bgcolor='#F8F9F9',
                            paper_bgcolor='#F8F9F9'
                        )
                    }
                
                protocols = list(stats.keys())
                bandwidth = [stats[p]['bytes_per_second'] for p in protocols]
                
                return {
                    'data': [
                        go.Bar(
                            x=protocols, 
                            y=bandwidth, 
                            name='Bandwidth (B/s)',
                            marker=dict(color='#9B59B6')
                        )
                    ],
                    'layout': go.Layout(
                        title='Protocol Bandwidth Usage',
                        xaxis={'title': 'Protocol'},
                        yaxis={'title': 'Bytes/sec'},
                        margin=dict(l=40, r=20, t=40, b=40),
                        plot_bgcolor='#F8F9F9',
                        paper_bgcolor='#F8F9F9'
                    )
                }
            except Exception as e:
                logger.error(f"Bandwidth chart error: {e}")
                return {
                    'data': [],
                    'layout': go.Layout(title='Error loading bandwidth data')
                }

        @self.app.callback(
            Output('top-ports-chart', 'figure'),
            [Input('slow-interval', 'n_intervals')]
        )
        def update_top_ports_chart(_):
            try:
                top_tcp = self.protocol_stats.get_top_ports('TCP', 5)
                top_udp = self.protocol_stats.get_top_ports('UDP', 5)
                
                if not top_tcp and not top_udp:
                    return {
                        'data': [],
                        'layout': go.Layout(
                            title='Waiting for port data...',
                            xaxis={'title': 'Port'},
                            yaxis={'title': 'Packet Count'},
                            margin=dict(l=40, r=20, t=40, b=40),
                            plot_bgcolor='#F8F9F9',
                            paper_bgcolor='#F8F9F9'
                        )
                    }
                
                data = []
                
                if top_tcp:
                    data.append(
                        go.Bar(
                            x=list(top_tcp.keys()), 
                            y=list(top_tcp.values()), 
                            name='TCP Ports',
                            marker=dict(color='#E74C3C')
                        )
                    )
                
                if top_udp:
                    data.append(
                        go.Bar(
                            x=list(top_udp.keys()), 
                            y=list(top_udp.values()), 
                            name='UDP Ports',
                            marker=dict(color='#F39C12')
                        )
                    )
                
                return {
                    'data': data,
                    'layout': go.Layout(
                        title='Top TCP & UDP Ports',
                        xaxis={'title': 'Port'},
                        yaxis={'title': 'Packet Count'},
                        margin=dict(l=40, r=20, t=40, b=40),
                        barmode='group',
                        plot_bgcolor='#F8F9F9',
                        paper_bgcolor='#F8F9F9'
                    )
                }
            except Exception as e:
                logger.error(f"Ports chart error: {e}")
                return {
                    'data': [],
                    'layout': go.Layout(title='Error loading port data')
                }

        # Flow Analysis callbacks
        @self.app.callback(
            Output('active-flows-table', 'children'),
            [Input('flow-update', 'n_intervals')]
        )
        def update_active_flows(_):
            if not self.flow_analyzer:
                return html.P("Flow analyzer not available")
            
            try:
                active_flows = self.flow_analyzer.get_active_flows(limit=20)
                
                if not active_flows:
                    return html.P("No active flows detected")
                
                # Create table headers
                headers = [
                    "Protocol", "Source", "Destination", "Duration (s)", 
                    "Packets", "Bytes", "Flow Type", "Last Activity"
                ]
                
                rows = []
                for flow in active_flows:
                    src = f"{flow['src_ip']}:{flow['src_port']}"
                    dst = f"{flow['dst_ip']}:{flow['dst_port']}"
                    duration = f"{flow['duration']:.1f}"
                    last_time = pd.to_datetime(flow['last_time'], unit='s').strftime('%H:%M:%S')
                    
                    rows.append(html.Tr([
                        html.Td(flow['protocol']),
                        html.Td(src),
                        html.Td(dst),
                        html.Td(duration),
                        html.Td(flow['packet_count']),
                        html.Td(flow['byte_count']),
                        html.Td(flow['flow_type']),
                        html.Td(last_time)
                    ]))
                
                return html.Table([
                    html.Thead(html.Tr([html.Th(h) for h in headers])),
                    html.Tbody(rows)
                ], className="table table-striped table-sm")
            except Exception as e:
                logger.error(f"Active flows error: {e}")
                return html.Div("Error loading flow data")

        @self.app.callback(
            Output('flow-types-chart', 'figure'),
            [Input('flow-update', 'n_intervals')]
        )
        def update_flow_types_chart(_):
            if not self.flow_analyzer:
                return {}
            
            try:
                flow_stats = self.flow_analyzer.get_flow_stats()
                flow_types = flow_stats.get('flow_types', {})
                
                if not flow_types:
                    return {
                        'data': [],
                        'layout': go.Layout(
                            title='Waiting for flow type data...',
                            margin=dict(l=20, r=20, t=40, b=20),
                            plot_bgcolor='#F8F9F9',
                            paper_bgcolor='#F8F9F9'
                        )
                    }
                
                return {
                    'data': [go.Pie(
                        labels=list(flow_types.keys()),
                        values=list(flow_types.values()),
                        hole=0.3,
                        marker=dict(
                            colors=[
                                '#3498DB', '#2ECC71', '#F1C40F', '#E74C3C', 
                                '#9B59B6', '#1ABC9C', '#F39C12', '#D35400'
                            ]
                        )
                    )],
                    'layout': go.Layout(
                        title='Flow Types',
                        margin=dict(l=20, r=20, t=40, b=20),
                        plot_bgcolor='#F8F9F9',
                        paper_bgcolor='#F8F9F9'
                    )
                }
            except Exception as e:
                logger.error(f"Flow types chart error: {e}")
                return {
                    'data': [],
                    'layout': go.Layout(title='Error loading flow type data')
                }

        @self.app.callback(
            Output('flow-duration-chart', 'figure'),
            [Input('flow-update', 'n_intervals')]
        )
        def update_flow_duration_chart(_):
            if not self.flow_analyzer:
                return {}
            
            try:
                all_flows = self.flow_analyzer.get_all_flows(limit=100)
                
                if not all_flows:
                    return {
                        'data': [],
                        'layout': go.Layout(
                            title='Waiting for flow duration data...',
                            xaxis={'title': 'Duration'},
                            yaxis={'title': 'Flow Count'},
                            margin=dict(l=40, r=20, t=40, b=40),
                            plot_bgcolor='#F8F9F9',
                            paper_bgcolor='#F8F9F9'
                        )
                    }
                
                # Group flows by duration ranges
                durations = [flow['duration'] for flow in all_flows]
                duration_labels = ['<1s', '1-5s', '5-30s', '30-60s', '1-5min', '>5min']
                
                # Ensure max duration is valid and greater than previous bin
                max_duration = max(durations) if durations else 600
                if max_duration <= 300:  # If max is less than or equal to previous bin
                    max_duration = 301   # Ensure it's greater
                
                duration_bins = [0, 1, 5, 30, 60, 300, max_duration]
                
                # Count flows in each bin
                binned_data = np.histogram(durations, bins=duration_bins)[0]
                
                return {
                    'data': [go.Bar(
                        x=duration_labels,
                        y=binned_data,
                        marker=dict(color='#F39C12')
                    )],
                    'layout': go.Layout(
                        title='Flow Duration Distribution',
                        xaxis={'title': 'Duration'},
                        yaxis={'title': 'Flow Count'},
                        margin=dict(l=40, r=20, t=40, b=40),
                        plot_bgcolor='#F8F9F9',
                        paper_bgcolor='#F8F9F9'
                    )
                }
            except Exception as e:
                logger.error(f"Flow duration chart error: {e}")
                return {
                    'data': [],
                    'layout': go.Layout(title='Error loading flow duration data')
                }

        @self.app.callback(
            Output('flow-network-graph', 'figure'),
            [Input('flow-update', 'n_intervals')]
        )
        def update_flow_network_graph(_):
            if not self.flow_analyzer:
                return {
                    'data': [],
                    'layout': go.Layout(
                        title='Flow analyzer not available',
                        margin=dict(b=20, l=5, r=5, t=40),
                        plot_bgcolor='#F8F9F9',
                        paper_bgcolor='#F8F9F9'
                    )
                }
            
            try:
                active_flows = self.flow_analyzer.get_active_flows(limit=50)
                
                if not active_flows:
                    return {
                        'data': [],
                        'layout': go.Layout(
                            title='No active flows to display',
                            margin=dict(b=20, l=5, r=5, t=40),
                            plot_bgcolor='#F8F9F9',
                            paper_bgcolor='#F8F9F9'
                        )
                    }
                
                # Create a graph of active flows
                nodes = set()
                edges = []
                edge_weights = {}
                
                for flow in active_flows:
                    src = flow['src_ip']
                    dst = flow['dst_ip']
                    nodes.add(src)
                    nodes.add(dst)
                    
                    edge_id = f"{src}|{dst}"
                    if edge_id in edge_weights:
                        edge_weights[edge_id] += flow['packet_count']
                    else:
                        edge_weights[edge_id] = flow['packet_count']
                        edges.append((src, dst))
                
                # Convert to lists for plotly
                nodes = list(nodes)
                
                # Create positions for nodes
                try:
                    import networkx as nx
                    G = nx.DiGraph()
                    
                    for node in nodes:
                        G.add_node(node)
                    
                    for src, dst in edges:
                        G.add_edge(src, dst, weight=edge_weights[f"{src}|{dst}"])
                    
                    # Use spring layout for positions
                    pos = nx.spring_layout(G, iterations=50)
                except:
                    # Fallback if networkx fails - create a simple circular layout
                    pos = {}
                    import math
                    n = len(nodes)
                    for i, node in enumerate(nodes):
                        angle = 2 * math.pi * i / n
                        pos[node] = [0.5 + 0.4 * math.cos(angle), 0.5 + 0.4 * math.sin(angle)]
                
                # Create node trace with minimal configuration
                node_x = []
                node_y = []
                node_text = []
                node_size = []
                
                for node in nodes:
                    x, y = pos[node]
                    node_x.append(x)
                    node_y.append(y)
                    node_text.append(node)
                    
                    # Calculate degree for size
                    degree = sum(1 for e in edges if e[0] == node or e[1] == node)
                    node_size.append(10 + degree * 3)
                
                node_trace = go.Scatter(
                    x=node_x, y=node_y,
                    mode='markers',
                    hoverinfo='text',
                    text=node_text,
                    marker=dict(
                        size=node_size,
                        color='blue',  # Simplify by using a single color
                        line=dict(width=1, color='darkblue')
                    )
                )
                
                # Create simplified edge traces
                edge_traces = []
                
                for edge in edges:
                    src, dst = edge
                    x0, y0 = pos[src]
                    x1, y1 = pos[dst]
                    weight = edge_weights[f"{src}|{dst}"]
                    
                    # Simple straight line
                    edge_trace = go.Scatter(
                        x=[x0, x1, None],  # None creates a break in the line
                        y=[y0, y1, None],
                        mode='lines',
                        line=dict(width=1 + weight/5, color='rgba(150, 150, 150, 0.7)'),
                        hoverinfo='text',
                        text=f"{src} → {dst} ({weight} packets)"
                    )
                    edge_traces.append(edge_trace)
                
                # Combine all traces
                data = edge_traces + [node_trace]
                
                return {
                    'data': data,
                    'layout': go.Layout(
                        title=f'Network Flow Graph - {len(nodes)} Nodes, {len(edges)} Connections',
                        showlegend=False,
                        hovermode='closest',
                        margin=dict(b=20, l=5, r=5, t=40),
                        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        plot_bgcolor='#F8F9F9',
                        paper_bgcolor='#F8F9F9'
                    )
                }
            except Exception as e:
                # Log the detailed error for debugging
                import traceback
                logger.error(f"Flow network graph error: {e}")
                logger.debug(f"Detailed error: {traceback.format_exc()}")
                
                # Return a simple error message
                return {
                    'data': [],
                    'layout': go.Layout(
                        title=f'Error loading flow network data: {str(e)}',
                        margin=dict(b=20, l=5, r=5, t=40),
                        plot_bgcolor='#F8F9F9',
                        paper_bgcolor='#F8F9F9'
                    )
                }
            except Exception as e:
                logger.error(f"Flow network graph error: {e}")
                return {
                    'data': [],
                    'layout': go.Layout(title='Error loading flow network data')
                }

# Flow selection callback
        @self.app.callback(
            [Output('selected-flow-info', 'children'),
             Output('flow-context-menu', 'disabled')],
            [Input('active-flows-table', 'selected_cells'),
             Input('active-flows-table', 'data')],
            prevent_initial_call=True
        )
        def handle_flow_selection(selected_cells, data):
            if not selected_cells or not data:
                return "No flow selected", True
            
            row_idx = selected_cells[0]['row']
            selected_flow = data[row_idx]
            
            flow_info = f"Selected: {selected_flow['src_ip']}:{selected_flow['src_port']} → {selected_flow['dst_ip']}:{selected_flow['dst_port']} ({selected_flow['protocol']})"
            
            return flow_info, False

        @self.app.callback(
            Output('download-pcap', 'data'),
            [Input('flow-context-menu', 'value')],
            [State('active-flows-table', 'selected_cells'),
             State('active-flows-table', 'data')],
            prevent_initial_call=True
        )
        def handle_flow_action(action, selected_cells, data):
            if not action or not selected_cells or not data:
                return dash.no_update
            
            row_idx = selected_cells[0]['row']
            selected_flow = data[row_idx]
            
            if action == 'export_pcap':
                # In a real implementation, you would filter packets based on flow info
                # and create a PCAP file with just those packets
                from network_analyzer.capture.pcap_handler import PCAPHandler
                import tempfile
                
                # Create temp file for PCAP
                temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pcap')
                temp_path = temp_file.name
                temp_file.close()
                
                src_ip = selected_flow['src_ip']
                dst_ip = selected_flow['dst_ip']
                src_port = selected_flow['src_port']
                dst_port = selected_flow['dst_port']
                protocol = selected_flow['protocol']
                
                timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                filename = f"flow_{src_ip}_{src_port}_to_{dst_ip}_{dst_port}_{timestamp}.pcap"
                
                # This is a placeholder - in reality you would export the actual flow packets
                return dcc.send_file(temp_path, filename=filename)
            
            # Reset dropdown
            return dash.no_update

    def setup_api_routes(self):
         @self.server.route("/api/health")
         def health():
             return jsonify({"status": "ok"})

         @self.server.route("/api/stats")
         def stats():
             if request.args.get("key") != API_KEY:
                 return jsonify({"error": "unauthorized"}), 403
             return jsonify({
                 "protocols": self.traffic_analyzer.protocol_counts,
                 "top_ips": self.traffic_analyzer.get_top_talkers(),
                 "alerts": self.security_analyzer.get_recent_alerts()
             })

         @self.server.route("/api/reset", methods=["POST"])
         def reset():
             if request.args.get("key") != API_KEY:
                 return jsonify({"error": "unauthorized"}), 403
             self.traffic_analyzer.protocol_counts.clear()
             self.traffic_analyzer.source_ips.clear()
             self.traffic_analyzer.destination_ips.clear()
             return jsonify({"status": "reset successful"})
         
         @self.server.route("/api/flows")
         def flows():
             if request.args.get("key") != API_KEY:
                 return jsonify({"error": "unauthorized"}), 403
             
             if not self.flow_analyzer:
                 return jsonify({"error": "flow analyzer not available"}), 404
             
             flow_type = request.args.get("type", "active")
             limit = int(request.args.get("limit", 50))
             
             if flow_type == "active":
                 data = self.flow_analyzer.get_active_flows(limit=limit)
             elif flow_type == "completed":
                 data = self.flow_analyzer.get_completed_flows(limit=limit)
             else:
                 data = self.flow_analyzer.get_all_flows(limit=limit)
             
             return jsonify({
                 "flows": data,
                 "stats": self.flow_analyzer.get_flow_stats(),
                 "duration_stats": self.flow_analyzer.get_flow_duration_stats()
             })

         @self.server.route("/api/pcap")
         def list_pcaps():
             if request.args.get("key") != API_KEY:
                 return jsonify({"error": "unauthorized"}), 403
             
             from network_analyzer.capture.pcap_handler import PCAPHandler
             pcap_handler = PCAPHandler()
             pcap_files = []
             
             try:
                 for filename in os.listdir(pcap_handler.output_dir):
                     if filename.endswith('.pcap'):
                         file_path = os.path.join(pcap_handler.output_dir, filename)
                         pcap_files.append({
                             "filename": filename,
                             "path": file_path,
                             "size": os.path.getsize(file_path),
                             "created": os.path.getctime(file_path)
                         })
             except Exception as e:
                 return jsonify({"error": str(e)}), 500
             
             return jsonify({"pcap_files": pcap_files})

    def run_server(self, host='0.0.0.0', port=8050):
        """
        Run the Dash application server
        
        Args:
            host: Host IP to listen on (default: '0.0.0.0' - all interfaces)
            port: Port to listen on (default: 8050)
        """
        try:
            logger.info(f"Starting dashboard on http://{host}:{port}")
            self.app.run(debug=False, host=host, port=port)
        except Exception as e:
            logger.error(f"Failed to start dashboard: {e}")
            raise