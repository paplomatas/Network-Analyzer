# network_analyzer/visualizer/graphs.py
import matplotlib.pyplot as plt
import pandas as pd
import io
import base64
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import networkx as nx

class NetworkGraphVisualizer:
    """
    Creates visualizations of network data
    """
    def __init__(self):
        self.plot_style = 'default'  # Can be changed to other matplotlib styles
    
    def create_traffic_over_time(self, times, counts, title="Network Traffic Over Time"):
        """Create a line graph showing traffic over time"""
        plt.style.use(self.plot_style)
        plt.figure(figsize=(10, 5))
        plt.plot(times, counts)
        plt.xlabel('Time')
        plt.ylabel('Packets per minute')
        plt.title(title)
        plt.grid(True, alpha=0.3)
        
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png')
        buffer.seek(0)
        plt.close()
        
        return buffer.getvalue()
    
    def create_protocol_pie(self, protocol_data, title="Protocol Distribution"):
        """Create a pie chart showing protocol distribution"""
        labels = list(protocol_data.keys())
        values = [data['count'] for data in protocol_data.values()]
        
        plt.style.use(self.plot_style)
        plt.figure(figsize=(8, 8))
        plt.pie(values, labels=labels, autopct='%1.1f%%')
        plt.title(title)
        
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png')
        buffer.seek(0)
        plt.close()
        
        return buffer.getvalue()
    
    def create_top_ips_bar(self, ip_data, direction='source', title=None, limit=10):
        """Create a bar chart showing top IPs"""
        if title is None:
            title = f'Top {direction.capitalize()} IPs'
        
        # Sort and limit data
        sorted_ips = sorted(ip_data.items(), key=lambda x: x[1], reverse=True)[:limit]
        ips = [item[0] for item in sorted_ips]
        counts = [item[1] for item in sorted_ips]
        
        plt.style.use(self.plot_style)
        plt.figure(figsize=(10, 6))
        plt.barh(ips, counts)
        plt.xlabel('Packet Count')
        plt.ylabel('IP Address')
        plt.title(title)
        plt.tight_layout()
        
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png')
        buffer.seek(0)
        plt.close()
        
        return buffer.getvalue()
    
    def create_network_map(self, connection_data):
        """Create a network graph visualization of host connections"""
        G = nx.DiGraph()
        
        # Add edges with weights
        for (src, dst), count in connection_data.items():
            G.add_edge(src, dst, weight=count)
        
        # Set node sizes based on degree
        degrees = dict(G.degree())
        node_sizes = [50 + v * 10 for v in degrees.values()]
        
        # Set edge widths based on weight
        edge_widths = [G[u][v]['weight'] * 0.5 for u, v in G.edges()]
        
        # Create plot
        plt.style.use(self.plot_style)
        plt.figure(figsize=(12, 12))
        
        # Use spring layout to position nodes
        pos = nx.spring_layout(G, seed=42)
        
        # Draw the graph
        nx.draw_networkx_nodes(G, pos, node_size=node_sizes, node_color='lightblue', alpha=0.8)
        nx.draw_networkx_edges(G, pos, width=edge_widths, alpha=0.5, edge_color='gray', arrows=True)
        nx.draw_networkx_labels(G, pos, font_size=8)
        
        plt.title('Network Connection Map')
        plt.axis('off')
        
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png')
        buffer.seek(0)
        plt.close()
        
        return buffer.getvalue()
    
    def create_plotly_protocol_timeseries(self, protocol_activity_data):
        """Create an interactive time series plot for protocol activity using Plotly"""
        fig = make_subplots(rows=2, cols=1, 
                           subplot_titles=('Packet Counts by Protocol', 'Bandwidth by Protocol'),
                           vertical_spacing=0.15)
        
        colors = ['rgb(31, 119, 180)', 'rgb(255, 127, 14)', 'rgb(44, 160, 44)', 
                 'rgb(214, 39, 40)', 'rgb(148, 103, 189)', 'rgb(140, 86, 75)']
        
        for i, (protocol, data) in enumerate(protocol_activity_data.items()):
            color_idx = i % len(colors)
            
            # Convert timestamps to datetime for better x-axis formatting
            time_bins = [pd.to_datetime(t, unit='s') for t in data['time_bins']]
            
            # Add packet count trace
            fig.add_trace(
                go.Scatter(
                    x=time_bins,
                    y=data['counts'],
                    mode='lines',
                    name=f'{protocol} (packets)',
                    line=dict(color=colors[color_idx]),
                ),
                row=1, col=1
            )
            
            # Add bandwidth trace
            fig.add_trace(
                go.Scatter(
                    x=time_bins,
                    y=data['bandwidth'],
                    mode='lines',
                    name=f'{protocol} (bandwidth)',
                    line=dict(color=colors[color_idx], dash='dash'),
                ),
                row=2, col=1
            )
        
        # Update layout
        fig.update_layout(
            height=800,
            title_text="Protocol Activity Over Time",
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1
            ),
            hovermode="x unified"
        )
        
        # Update x-axis properties
        fig.update_xaxes(title_text="Time", row=2, col=1)
        
        # Update y-axis properties
        fig.update_yaxes(title_text="Packet Count", row=1, col=1)
        fig.update_yaxes(title_text="Bandwidth (bytes)", row=2, col=1)
        
        return fig.to_html(include_plotlyjs='cdn', full_html=False)
    
    def create_port_heatmap(self, port_data, title="Port Activity Heatmap"):
        """Create a heatmap of port activity"""
        # Convert port data to a format suitable for heatmap
        # port_data should be a dictionary with (source_port, dest_port) as keys and count as values
        
        # Extract unique source and destination ports
        all_pairs = list(port_data.keys())
        src_ports = sorted(set([p[0] for p in all_pairs]))
        dst_ports = sorted(set([p[1] for p in all_pairs]))
        
        # Create dataframe for heatmap
        heatmap_data = pd.DataFrame(0, index=src_ports, columns=dst_ports)
        for (src, dst), count in port_data.items():
            heatmap_data.at[src, dst] = count
        
        # If there are too many ports, limit to the most active ones
        if len(src_ports) > 20 or len(dst_ports) > 20:
            # Calculate total activity for each port
            src_totals = heatmap_data.sum(axis=1)
            dst_totals = heatmap_data.sum(axis=0)
            
            # Get top 20 ports
            top_src = src_totals.nlargest(20).index
            top_dst = dst_totals.nlargest(20).index
            
            # Filter dataframe to include only top ports
            heatmap_data = heatmap_data.loc[top_src, top_dst]
        
        plt.style.use(self.plot_style)
        plt.figure(figsize=(12, 10))
        plt.imshow(heatmap_data, cmap='YlOrRd')
        plt.colorbar(label='Packet Count')
        
        # Add labels
        plt.xticks(range(len(heatmap_data.columns)), heatmap_data.columns, rotation=90)
        plt.yticks(range(len(heatmap_data.index)), heatmap_data.index)
        
        plt.xlabel('Destination Port')
        plt.ylabel('Source Port')
        plt.title(title)
        plt.tight_layout()
        
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png')
        buffer.seek(0)
        plt.close()
        
        return buffer.getvalue()
    
    def create_anomaly_timeline(self, anomaly_data, normal_traffic_data, title="Network Anomaly Detection"):
        """Create a timeline of anomalies overlaid on normal traffic"""
        times = normal_traffic_data['times']
        counts = normal_traffic_data['counts']
        
        plt.style.use(self.plot_style)
        plt.figure(figsize=(12, 6))
        
        # Plot normal traffic
        plt.plot(times, counts, label='Normal Traffic', color='blue', alpha=0.7)
        
        # Overlay anomalies
        for anomaly in anomaly_data:
            plt.axvspan(anomaly['start_time'], anomaly['end_time'], alpha=0.3, color='red')
            
            # Add annotation for severe anomalies
            if anomaly.get('severity', 0) > 0.7:
                plt.annotate(
                    anomaly.get('type', 'High Severity Anomaly'),
                    xy=(anomaly['start_time'], max(counts) * 0.9),
                    xytext=(anomaly['start_time'], max(counts) * 0.95),
                    arrowprops=dict(facecolor='black', shrink=0.05),
                    horizontalalignment='center',
                )
        
        plt.xlabel('Time')
        plt.ylabel('Traffic Volume')
        plt.title(title)
        plt.grid(True, alpha=0.3)
        plt.legend()
        
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png')
        buffer.seek(0)
        plt.close()
        
        return buffer.getvalue()
    
    def create_security_threats_radar(self, threat_data, title="Security Threat Assessment"):
        """Create a radar chart of security threats by category"""
        categories = list(threat_data.keys())
        values = [threat_data[cat] for cat in categories]
        
        # Create radar chart
        fig = go.Figure()
        
        fig.add_trace(go.Scatterpolar(
            r=values,
            theta=categories,
            fill='toself',
            name='Threat Level'
        ))
        
        fig.update_layout(
            polar=dict(
                radialaxis=dict(
                    visible=True,
                    range=[0, max(values) * 1.2]
                )),
            showlegend=False,
            title=title
        )
        
        return fig.to_html(include_plotlyjs='cdn', full_html=False)
    
    def encode_image_base64(self, img_bytes):
        """Convert image bytes to base64 encoded string for HTML embedding"""
        return base64.b64encode(img_bytes).decode('utf-8')
    
    def set_style(self, style_name):
        """Change the matplotlib style"""
        if style_name in plt.style.available:
            self.plot_style = style_name
        else:
            print(f"Style {style_name} not available. Using default.")
            self.plot_style = 'default'