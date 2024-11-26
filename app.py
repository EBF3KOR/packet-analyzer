from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from scapy import rdpcap, IP, TCP, UDP, Ether, IPv6
import pandas as pd
import numpy as np
import pytz
import matplotlib
matplotlib.use('Agg')  
import matplotlib.pyplot as plt
import networkx as nx
import os
import re
import seaborn as sns
import matplotlib.ticker as ticker
from collections import defaultdict
def process_packets(packets):
    # Define fields to extract
    ip_fields = ['src', 'dst', 'proto', 'ttl', 'id']
    ipv6_fields = ['src', 'dst', 'plen', 'hlim']  # IPv6 specific fields
    tcp_fields = ['sport', 'dport', 'flags', 'seq', 'ack', 'window']
    udp_fields = ['sport', 'dport']
    
    window_data = []
    # List to hold packet data
    packet_data = []
    udp_cnt = 0
    tcp_cnt = 0

    # Iterate through packets
    for packet in packets:
        # Initialize with None for each field
        packet_info = {field: None for field in ip_fields + ipv6_fields + 
                       ['time', 'Protocol', 'payload', 'data_length', 
                        'payload_length', 'Ethernet_src', 'Ethernet_dst', 
                        'Ethernet_type', 'Datetime']}

        # Extract fields from Ethernet layer
        if packet.haslayer(Ether):
            eth = packet[Ether]
            packet_info['Ethernet_src'] = eth.src
            packet_info['Ethernet_dst'] = eth.dst
            packet_info['Ethernet_type'] = eth.type

        # Extract fields from IPv4 layer
        if packet.haslayer(IP):
            ip = packet[IP]
            for field in ip_fields:
                packet_info[field] = getattr(ip, field, None)  # Include IP fields
            packet_info['time'] = packet.time  # Add timestamp

            # Determine protocol type and calculate data length
            if packet.haslayer(TCP):
                packet_info['Protocol'] = 'TCP'
                tcp = packet[TCP]
                tcp_cnt += 1
                window_data.append((packet_info['time'], tcp.window))
                # Calculate data length (Total Length - TCP Header Length)
                ip_payload_length = len(ip.payload)  # Get the length of the IP payload
                tcp_header_length = 20  # TCP header length in bytes
                data_length = ip_payload_length - tcp_header_length
                packet_info['data_length'] = data_length if data_length > 0 else 0
                
                # Handle TCP payload if present
                packet_info['payload'] = bytes(tcp.payload) if tcp.payload else None
                packet_info['payload_length'] = len(packet_info['payload']) if packet_info['payload'] else 0  # Payload length

                # Extract TCP fields
                for field in tcp_fields:
                    packet_info[field] = getattr(tcp, field, None)

            elif packet.haslayer(UDP):
                udp = packet[UDP]
                if udp.sport == 5353 or udp.dport == 5353:  # Check for mDNS port
                    packet_info['Protocol'] = 'mDNS (UDP)'
                else:
                    packet_info['Protocol'] = 'UDP'
                udp_cnt += 1

                # Calculate data length (Total Length - UDP Header Length)
                total_length = len(udp)  # Get the length of the entire UDP packet (header + payload)
                udp_payload_length = total_length - 8  # Subtract UDP header length (8 bytes)
                packet_info['data_length'] = udp_payload_length if udp_payload_length > 0 else 0
                
                # Handle UDP payload if present
                packet_info['payload'] = bytes(udp.payload) if udp.payload else None
                packet_info['payload_length'] = len(packet_info['payload']) if packet_info['payload'] else 0  # Payload length

                # Extract UDP fields
                for field in udp_fields:
                    packet_info[field] = getattr(udp, field, None)

            else:
                packet_info['Protocol'] = 'Other'  

        # Extract fields from IPv6 layer
        elif packet.haslayer(IPv6):
            ipv6 = packet[IPv6]
            for field in ipv6_fields:
                packet_info[field] = getattr(ipv6, field, None)  # Include IPv6 fields
            packet_info['time'] = packet.time  # Add timestamp
            packet_info['Protocol'] = 'IPv6'  # Indicate that this is an IPv6 packet

            # Calculate data length based on IPv6 payload and headers
            if packet.haslayer(UDP):
                udp = packet[UDP]
                total_length = len(udp)  # Get the length of the entire UDP packet
                udp_payload_length = total_length - 8  # Subtract UDP header length (8 bytes)
                packet_info['data_length'] = udp_payload_length if udp_payload_length > 0 else 0
                packet_info['payload'] = bytes(udp.payload) if udp.payload else None
                packet_info['payload_length'] = len(packet_info['payload']) if packet_info['payload'] else 0  # Payload length

                # Extract UDP fields
                for field in udp_fields:
                    packet_info[field] = getattr(udp, field, None)

        # Append the packet info to the list
        packet_data.append(packet_info)

    # Create a DataFrame
    df = pd.DataFrame(packet_data)

    # Convert the 'time' column to datetime
    df['Datetime'] = pd.to_numeric(df['time'])
    df['Datetime'] = pd.to_datetime(df['Datetime'], unit='s')

    # Drop the 'options' column if it exists
    if 'options' in df.columns:
        df.drop(columns=['options'], inplace=True)
    
    # Define IST timezone
    ist = pytz.timezone('Asia/Kolkata')

    # Convert the 'Datetime' column from UTC to IST
    df['Datetime'] = df['Datetime'].dt.tz_localize('UTC').dt.tz_convert(ist)
    return df
def plot_network_graph(df):
    # Filter out rows with NaN in 'src' or 'dst'
    df_filtered = df.dropna(subset=['src', 'dst'])

    # Regular expression pattern for matching IPv4 addresses
    ipv4_pattern = re.compile(
        r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    )

    # Function to check if an IP is a valid IPv4 address
    def is_valid_ipv4(ip):
        return bool(ipv4_pattern.match(ip)) and all(0 <= int(part) < 256 for part in ip.split('.'))

    # Filter only rows with valid IPv4 addresses
    df_filtered = df_filtered[df_filtered['src'].apply(is_valid_ipv4) & df_filtered['dst'].apply(is_valid_ipv4)]

    G = nx.DiGraph()
    for index, row in df_filtered.iterrows():
        src_ip = row['src']
        dst_ip = row['dst']
        G.add_edge(src_ip, dst_ip)

    plt.figure(figsize=(10, 8))
    pos = nx.spring_layout(G, k=0.3, iterations=20)
    nx.draw(G, pos, with_labels=True, node_size=3000, node_color="lightblue",
            font_size=10, font_weight="bold", edge_color="gray")
    plt.title('Network Graph of IP Communication (IPv4 Only)', fontsize=15)

    # Save the plot as an image
    plot_path = os.path.join(app.config['UPLOAD_FOLDER'], 'network_graph.png')
    plt.savefig(plot_path)
    plt.close()  # Close the plot to free memory

    return  plot_path
def is_device_ip(ip):
    if pd.isna(ip):
        return False
    # Regular expression to match valid IPv4 addresses
    ipv4_pattern = r'^(?!0)(?!.*\.$)(?!.*\.\.)(?!.*\.$)([0-9]{1,3}\.){3}[0-9]{1,3}$'
    
    # Exclude broadcast, multicast, and link-local addresses
    if (re.match(ipv4_pattern, ip) is None or 
        ip.startswith('224.') or 
        ip.startswith('255.') or 
        ip.endswith('.255') or 
        ip == '0.0.0.0'):
            return False
    return True
def identify_device_ips(df):
    def is_device_ip(ip):
        if pd.isna(ip):
            return False
        # Regular expression to match valid IPv4 addresses
        ipv4_pattern = r'^(?!0)(?!.*\.$)(?!.*\.\.)(?!.*\.$)([0-9]{1,3}\.){3}[0-9]{1,3}$'
        
        # Exclude broadcast, multicast, and link-local addresses
        if (re.match(ipv4_pattern, ip) is None or 
            ip.startswith('224.') or 
            ip.startswith('255.') or 
            ip.endswith('.255') or 
            ip == '0.0.0.0'):
            return False
        return True

    # Apply the filter to the source and destination address columns
    device_src_ips = df[df['src'].apply(is_device_ip)]
    device_dst_ips = df[df['dst'].apply(is_device_ip)]

    # Combine the filtered source and destination IPs to find unique device IPs
    device_ips = pd.concat([device_src_ips['src'], device_dst_ips['dst']]).unique()

    return device_ips
def identify_drives(df):
    mask1= df[(df['Ethernet_src'].str.startswith('00:60')) & (df['Protocol'].notnull())] 
    mask2=df[(df['Ethernet_dst'].str.startswith('00:60')) & (df['Protocol'].notnull())] 
    ip_values = pd.concat([mask1['src'], mask2['dst']]).unique()
    print(ip_values)
    return ip_values

# Function to count IP protocols
def count_ip_protocols(df):
    source_counts = df.groupby(['src', 'Protocol']).size().reset_index(name='count')
    destination_counts = df.groupby(['dst', 'Protocol']).size().reset_index(name='count')
    return source_counts, destination_counts
def plot_communication_heatmap(df):
    comm_matrix = df.groupby(['src', 'dst']).size().unstack(fill_value=0)
    plt.figure(figsize=(10, 8))
    sns.heatmap(comm_matrix, annot=True, cmap='Blues', fmt='d')
    plt.title('Heatmap of Communications between Source and Destination IPs', fontsize=15)
    plt.xlabel('Destination IP')
    plt.ylabel('Source IP')

    plt.show()
    plot_path = os.path.join(app.config['UPLOAD_FOLDER'], 'plot_communication_heatmap.png')
    plt.savefig(plot_path)
    plt.close()  

    return plot_path

def plot_packet_io_graph(df, datetime_col='Datetime', resample_interval='1s'):  # Change '1S' to '1s'
    df[datetime_col] = pd.to_datetime(df[datetime_col])
    df_resampled = df.set_index(datetime_col).resample(resample_interval).size().reset_index(name='packet_count')
    plt.figure(figsize=(12, 6))
    plt.plot(df_resampled[datetime_col], df_resampled['packet_count'], marker='o', linestyle='-')
    plt.title('I/O Graph: Packet Count Over Time (1 Second Intervals)')
    plt.xlabel('Time')
    plt.ylabel('Number of Packets')
    plt.ylim(0, df_resampled['packet_count'].max() * 1.1)
    plt.grid()
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()
    
    plot_path = os.path.join(app.config['UPLOAD_FOLDER'], 'io_graph.png')
    plt.savefig(plot_path)
    plt.close()  
    return plot_path

# Function to identify inactivity gaps
def identify_inactivity_gaps(df, threshold_seconds=2):
    df_sorted = df.sort_values(by='Datetime')
    df_sorted['time_diff'] = df_sorted['Datetime'].diff()
    threshold = pd.Timedelta(seconds=threshold_seconds)
    gaps = df_sorted[df_sorted['time_diff'] > threshold]
    return gaps[['Datetime', 'time_diff']]


def mark_retransmissions_with_set(df):
    # Create a new column to mark retransmissions
    df['is_retransmission'] = False
    
    # Create a set to track seen packets
    seen_packets = set()
    
    # Iterate through the DataFrame to identify retransmissions
    for i, row in df.iterrows():
        packet_id = (row['sport'], row['dport'], row['seq'], row['ack'], row['flags'])
        
        if packet_id in seen_packets:
            df.at[i, 'is_retransmission'] = True
        else:
            seen_packets.add(packet_id)
    
    # Return the DataFrame with retransmission info
    return df

def identify_duplicate_packets(df):
   
    result_df = df.copy()
    
    # Initialize duplicate flags
    result_df['is_tcp_retransmission'] = False
    result_df['is_tcp_dup_ack'] = False
    result_df['is_duplicate_packet'] = False
    
    # Convert time to float if it's not already
    result_df['time'] = result_df['time'].astype(float)
    
    # Process TCP packets
    tcp_packets = result_df[result_df['Protocol'] == 'TCP'].copy()
    
    if not tcp_packets.empty:
        # Sort by time to maintain temporal order
        tcp_packets = tcp_packets.sort_values('time')
        
        # Group by connection tuple
        connections = tcp_packets.groupby(['src', 'dst', 'sport', 'dport'])
        
        for _, connection in connections:
            connection = connection.sort_values('time')
            
            for i in range(1, len(connection)):
                current = connection.iloc[i]
                previous = connection.iloc[i-1]
                
                
                
                # Check for duplicate ACKs
                # Conditions:
                # 1. Same ACK number
                # 2. Zero payload length
                # 3. Different sequence numbers
                if (current['ack'] == previous['ack'] and
                    current['payload_length'] == 0 and
                    current['seq'] != previous['seq']):
                    result_df.loc[current.name, 'is_tcp_dup_ack'] = True
                
                # Check for exact duplicate packets
                # Conditions:
                # 1. Same everything except time
                if (current['seq'] == previous['seq'] and
                    current['ack'] == previous['ack'] and
                    current['payload_length'] == previous['payload_length'] and
                    current['flags'] == previous['flags'] and
                    current['payload'] == previous['payload']):
                    result_df.loc[current.name, 'is_duplicate_packet'] = True
    
    # Calculate statistics
    '''stats = {
        'total_packets': len(df),
        'tcp_packets': len(df[df['Protocol'] == 'TCP']),
        'tcp_retransmissions': result_df['is_tcp_retransmission'].sum(),
        'tcp_dup_acks': result_df['is_tcp_dup_ack'].sum(),
        'exact_duplicates': result_df['is_duplicate_packet'].sum()
    }
    
    # Add percentage calculations
    if stats['tcp_packets'] > 0:
        stats['retransmission_percentage'] = (stats['tcp_retransmissions'] / stats['tcp_packets']) * 100
        stats['dup_ack_percentage'] = (stats['tcp_dup_acks'] / stats['tcp_packets']) * 100
    else:
        stats['retransmission_percentage'] = 0
        stats['dup_ack_percentage'] = 0
    '''
    return result_df


# Function to calculate bandwidth
def calculate_bandwidth(df,devices, link_capacity_mbps=100):
    
    df_copy = df.copy()
    
    df_copy['payload_length'] = df_copy['payload_length'].fillna(0)
    
    total_data_transmitted_bytes = df_copy['payload_length'].sum()
    time_duration_seconds = (df_copy['Datetime'].iloc[-1] - df_copy['Datetime'].iloc[0]).total_seconds()
    actual_bandwidth_bps = total_data_transmitted_bytes * 8 / time_duration_seconds
    actual_bandwidth_mbps = actual_bandwidth_bps / 1_000_000
    available_bandwidth_mbps = link_capacity_mbps - actual_bandwidth_mbps
    available_bandwidth_bytes_per_second =available_bandwidth_mbps  * (10**6 / 8)
    actual_bandwidth_per_device = actual_bandwidth_mbps/devices
    actual_bandwidth_per_device_bytes = actual_bandwidth_per_device * (10**6 / 8)
    number_of_devices = round(available_bandwidth_bytes_per_second /actual_bandwidth_per_device_bytes  )    
    return {
        'Total Data Transmitted (bits)': total_data_transmitted_bytes * 8,
        'Time Duration (seconds)': time_duration_seconds,
        'Actual Bandwidth Used (Mbps)': actual_bandwidth_mbps,
        'Available Bandwidth (Mbps)': available_bandwidth_mbps,
        'devices':number_of_devices
    }


def visual_bandwidth(actual_bandwidth_mbps, available_bandwidth_mbps,link_capacity_mbps=100):
    # Prepare data for visualization
    labels = ['Actual Bandwidth Used', 'Available Bandwidth']
    values = [actual_bandwidth_mbps, available_bandwidth_mbps]
    
    # Create a bar chart
    plt.figure(figsize=(8, 5))
    bars = plt.bar(labels, values, color=['blue', 'green'], width=0.4)
    
    # Annotate bars with actual values
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval, f'{yval:.6f}', ha='center', va='bottom')
    
    # Format y-axis to show decimals
    plt.gca().yaxis.set_major_formatter(ticker.FormatStrFormatter('%.6f'))
    
    # Add horizontal line for link capacity
    plt.axhline(y=link_capacity_mbps, color='black', linestyle='--', label='Link Capacity (100 Mbps)')
    
    # Additional plot formatting
    plt.ylabel('Bandwidth (Mbps)')
    plt.title('Bandwidth Usage vs Available Bandwidth')
    plt.ylim(0, link_capacity_mbps)  # Set y-axis limit to link capacity
    plt.legend()
    plt.tight_layout()
    plt.show()
    plot_path = os.path.join(app.config['UPLOAD_FOLDER'], 'bandwidth.png')
    plt.savefig(plot_path)
    plt.close()  
    return plot_path
# Function to calculate efficiency



def calculate_ipv4_bandwidth(df,available_bandwidth_mbps):
    ipv4_df = df[df['Protocol'].isin(['TCP', 'UDP', 'Other'])]
    device_data = defaultdict(int)
    device_packets = defaultdict(int)

    start_time = ipv4_df['Datetime'].min()
    end_time = ipv4_df['Datetime'].max()
    total_time = (pd.to_datetime(end_time) - pd.to_datetime(start_time)).total_seconds()

    for _, row in ipv4_df.iterrows():
        src_ip = row['src']
        data_length = row['data_length']
        if is_device_ip(src_ip):
            device_data[src_ip] += data_length
            device_packets[src_ip] += 1

    results = []
    for device, total_bytes in device_data.items():
        bandwidth_bps = (total_bytes * 8) / total_time
        bandwidth_mbps = bandwidth_bps / 1_000_000
        packets = device_packets[device]
        available_bandwidth_bytes_per_second =available_bandwidth_mbps * (10**6 / 8)
        actual_bandwidth_bps = bandwidth_bps
        number_of_devices = round(available_bandwidth_bytes_per_second / actual_bandwidth_bps) 
        results.append({
            'IP': device,
            'Total_Data_Sent': total_bytes,
            'Total_Packets_Sent': packets,
            'Bandwidth_bps': bandwidth_bps,
            'Bandwidth_Mbps': bandwidth_mbps,
            'Avg_Packet_Size': total_bytes / packets if packets > 0 else 0,
            'No_of_Devices_can_be_connected': number_of_devices
        })

    return pd.DataFrame(results)

def calculate_efficiency(df):
    total_data_length = df['data_length'].sum()
    if not df.empty:
        total_time = df['Datetime'].iloc[-1] - df['Datetime'].iloc[0]
        total_time_seconds = total_time.total_seconds()
    else:
        total_time_seconds = 0
    efficiency = total_data_length / total_time_seconds if total_time_seconds > 0 else 0
    return {
        'Total Data Length (bytes)': total_data_length,
        'Total Time (seconds)': total_time_seconds,
        'Efficiency (bytes/second)': efficiency
    }
 
# Function to analyze TCP latencies
def analyze_tcp_latencies(df):
    TCP_df = df[df['Protocol'] == 'TCP'].copy()
    TCP_df['Datetime'] = pd.to_datetime(TCP_df['Datetime'])
    TCP_df.reset_index(drop=True, inplace=True)
    TCP_df = TCP_df.sort_values('Datetime')
    time_diffs = []
    mean_latencies = []
    n = len(TCP_df)
    i = 0
    total_time_diff = 0
    cnt = 0
 
    while i < n - 1:
        current_time = TCP_df.iloc[i]['Datetime']
        next_time = TCP_df.iloc[i + 1]['Datetime']
        time_diff = (next_time - current_time).total_seconds()
        total_time_diff += time_diff
        cnt += 1
        time_diffs.append(time_diff)
 
        if TCP_df.iloc[i + 1]['flags'] == 'A':
            mean_latency = total_time_diff / cnt if cnt > 0 else 0
            mean_latencies.append(mean_latency)
            if mean_latency > 10:
                print("Packet with latency > 10 seconds:", TCP_df.iloc[i].to_dict())
            total_time_diff = 0
            cnt = 0
            i += 2  
        else:
            i += 1  
 
    average_latency = sum(mean_latencies) / len(mean_latencies) if mean_latencies else 0
    outliers = identify_outliers(mean_latencies)
    return {
        'Average Latency': average_latency,
        'Mean Latencies': mean_latencies,
        'Outliers': outliers
    }
 
# Function to identify outliers
def identify_outliers(mean_latencies):
    mean_latencies_array = np.array(mean_latencies)
    Q1 = np.percentile(mean_latencies_array, 25)
    Q3 = np.percentile(mean_latencies_array, 75)
    IQR = Q3 - Q1
    lower_bound = Q1 - 1.5 * IQR
    upper_bound = Q3 + 1.5 * IQR
    outliers = mean_latencies_array[(mean_latencies_array < lower_bound) | (mean_latencies_array > upper_bound)]
    return outliers


def window_size_analysis_Devices(df, device_ips, output_dir='uploads/'):
    analysis_results = {}  # Store results for each device
    os.makedirs(output_dir, exist_ok=True)  # Ensure the output directory exists

    for device in device_ips:
        TCP_df = df[(df['Protocol'] == 'TCP') & (df['src'] == device)]
        
        if not TCP_df.empty:
            avg_window_size = TCP_df['window'].mean()
            window_size_variation = TCP_df['window'].std()
            analysis_results[device] = {
                'avg_window_size': avg_window_size,
                'window_size_variation': window_size_variation,
                'inferences': []
            }

            # Inferences based on average window size and variation
            if avg_window_size > 30000:
                analysis_results[device]['inferences'].append("Average TCP Window Size is high, indicating good potential for data transmission.")
            else:
                analysis_results[device]['inferences'].append("Average TCP Window Size is low, suggesting potential underutilization of bandwidth.")

            if window_size_variation > 25000:
                analysis_results[device]['inferences'].append("High variation in TCP Window Size detected, indicating potential network instability or congestion.")
            else:
                analysis_results[device]['inferences'].append("Low variation in TCP Window Size suggests stable network conditions.")

            # Additional checks for specific thresholds
            if avg_window_size > 50000 and window_size_variation < 20000:
                analysis_results[device]['inferences'].append("Optimal conditions detected: High average window size with low variability.")
            elif avg_window_size < 20000 and window_size_variation > 25000:
                analysis_results[device]['inferences'].append("Critical condition: Low average window size with high variability, indicating severe network issues.")

            # Generate a plot for TCP window size over time
            plt.figure(figsize=(12, 6))
            plt.plot(TCP_df['time'], TCP_df['window'], label='TCP Window Size', marker='o', linestyle='-')
            plt.xlabel('Time')
            plt.ylabel('TCP Window Size (Bytes)')
            plt.title(f'TCP Window Size Over Time for {device}')
            plt.xticks(rotation=45)
            plt.legend()
            plt.grid()
            plt.tight_layout()

            # Save the plot as a PNG file
            plot_filename = f'window_size_{device.replace(".", "_")}.png'  # Replace dots in IP with underscores for filename
            plt.savefig(os.path.join(output_dir, plot_filename))
            plt.close()  # Close the figure to free up memory
            
            # Add the plot filename to the results
            analysis_results[device]['plot'] = plot_filename

    return analysis_results

def analyze_tcp_flags(df):
    """
    Analyzes TCP flags to identify connection patterns and potential issues.
    """
    tcp_df = df[df['Protocol'] == 'TCP'].copy()
    
    # Initialize counters for different types of connections
    analysis = {
        'total_connections': 0,
        'successful_connections': 0,
        'failed_connections': 0,
        'reset_connections': 0,
        'incomplete_connections': 0,
        'suspicious_patterns': []
    }
    
    # Group by source-destination pairs
    connections = tcp_df.groupby(['src', 'dst'])
    
    for _, connection in connections:
        analysis['total_connections'] += 1
        flags_sequence = connection['flags'].tolist()
        
        # Check for complete 3-way handshake (SYN -> SYN-ACK -> ACK)
        if any('S' in str(f) for f in flags_sequence) and \
           any('SA' in str(f) for f in flags_sequence) and \
           any(f == 'A' for f in flags_sequence):
            analysis['successful_connections'] += 1
            
        # Check for reset connections
        if any('R' in str(f) for f in flags_sequence):
            analysis['reset_connections'] += 1
            
        # Check for failed connection attempts
        if any('S' in str(f) for f in flags_sequence) and not any('SA' in str(f) for f in flags_sequence):
            analysis['failed_connections'] += 1
            
        # Check for incomplete connections
        if any('S' in str(f) for f in flags_sequence) and not any('F' in str(f) for f in flags_sequence):
            analysis['incomplete_connections'] += 1
            
        # Identify suspicious patterns
        if len(flags_sequence) > 10 and all(f == 'S' for f in flags_sequence):
            analysis['suspicious_patterns'].append({
                'src': connection['src'].iloc[0],
                'dst': connection['dst'].iloc[0],
                'pattern': 'Possible SYN flood attack'
            })
            
    # Structure the results in a format suitable for rendering in HTML
    html_results = {
        'total_connections': analysis['total_connections'],
        'successful_connections': analysis['successful_connections'],
        'failed_connections': analysis['failed_connections'],
        'reset_connections': analysis['reset_connections'],
        'incomplete_connections': analysis['incomplete_connections'],
        'suspicious_patterns': analysis['suspicious_patterns']
    }
    
    return html_results

def analyze_protocol_distribution(df):
    """
    Analyzes the distribution of protocols and their usage patterns.
    """
    protocol_stats = {
        'protocol_counts': df['Protocol'].value_counts().to_dict(),
        'protocol_bytes': df.groupby('Protocol')['data_length'].sum().to_dict(),
        'protocol_trends': {}
    }
    
    # Analyze temporal trends
    df['hour'] = df['Datetime'].dt.hour
    hourly_protocols = df.groupby(['hour', 'Protocol']).size().unstack(fill_value=0)
    protocol_stats['hourly_distribution'] = hourly_protocols.to_dict()
    
    return protocol_stats




def calculate_network_metrics(df):
    """
    Calculates various network performance metrics.
    """
    metrics = {
        'overall_metrics': {},
        'per_protocol_metrics': {},
        'time_based_metrics': {}
    }
    
    # Overall metrics
    total_duration = (df['Datetime'].max() - df['Datetime'].min()).total_seconds()
    metrics['overall_metrics'] = {
        'total_packets': len(df),
        'total_bytes': df['payload_length'].sum(),
        'packets_per_second': len(df) / total_duration if total_duration > 0 else 0,
        'bytes_per_second': df['payload_length'].sum() / total_duration if total_duration > 0 else 0,
        'unique_hosts': len(set(df['src'].unique()) | set(df['dst'].unique()))
    }
    
    # Per-protocol metrics
    for protocol in df['Protocol'].unique():
        proto_df = df[df['Protocol'] == protocol]
        metrics['per_protocol_metrics'][protocol] = {
            'packet_count': len(proto_df),
            'byte_count': proto_df['payload_length'].sum(),
            'percentage': (len(proto_df) / len(df)) * 100,
            'average_packet_size': proto_df['payload_length'].mean()
        }
    
    # Time-based metrics (hourly)
    df['hour'] = df['Datetime'].dt.hour
    hourly_stats = df.groupby('hour').agg({
        'data_length': ['count', 'sum', 'mean'],
        'Protocol': 'nunique'
    })
    
    metrics['time_based_metrics'] = {
        'peak_hour': hourly_stats['data_length']['count'].idxmax(),
        'quiet_hour': hourly_stats['data_length']['count'].idxmin(),
        'hourly_packet_counts': hourly_stats['data_length']['count'].to_dict(),
        'hourly_data_volumes': hourly_stats['data_length']['sum'].to_dict()
    }
    
    return metrics
# Homepage route
app = Flask(__name__)
CORS(app)
app.config['UPLOAD_FOLDER'] = 'uploads/'

# Ensure the uploads directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

from flask import send_from_directory

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
# Homepage route
@app.route('/')
def index():
    return render_template('index.html')

# Route to upload file
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return render_template('index.html', error="No file part")
   
    file = request.files['file']
    if file.filename == '':
        return render_template('index.html', error="No selected file")
   
    if file and file.filename.endswith('.pcap'):
        # Ensure the uploads directory exists
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        # Analyze the PCAP file
        packets = rdpcap(file_path)
        df=process_packets(packets)
        df['Datetime'] = pd.to_datetime(df['Datetime'])  # Ensure Datetime is parsed

        # Perform analyses
        
        plot_path = plot_network_graph(df)
        source_counts, destination_counts = count_ip_protocols(df)
        calculate_network_metric=calculate_network_metrics(df)
        device_ips=identify_device_ips(df)
        drives=identify_drives(df)
        device_ips = device_ips.tolist() 
        drives = drives.tolist() 
        plot_heatmap=plot_communication_heatmap(df)
        io_graph=plot_packet_io_graph(df)
        inactivity_gaps = identify_inactivity_gaps(df)
        df = mark_retransmissions_with_set(df)
        retransmission_packets=df[df['is_retransmission']==True]
        retransmission_packets=retransmission_packets[retransmission_packets['flags']!='R']
        df= identify_duplicate_packets(df)
        duplicate_packets = df[df['is_duplicate_packet']==True]
        duplicate_packets =duplicate_packets[duplicate_packets['flags'].str.contains('F', na=False) ]
        bandwidth = calculate_bandwidth(df,devices=len(device_ips))
        efficiency = calculate_efficiency(df)
        tcp_latencies = analyze_tcp_latencies(df)
        Outliers=identify_outliers(tcp_latencies['Mean Latencies'])
        inactivity_gaps['time_diff'] = inactivity_gaps['time_diff'].dt.total_seconds()
        bandwidth_graph=visual_bandwidth(bandwidth['Actual Bandwidth Used (Mbps)'],bandwidth['Available Bandwidth (Mbps)'])
        bandwidth_df = calculate_ipv4_bandwidth(df,bandwidth['Available Bandwidth (Mbps)'])
        analyze_tcp_flag=analyze_tcp_flags(df)
         
        window_analysis_results = window_size_analysis_Devices(df, identify_drives(df))
        # Pass results back to the index page
        return render_template('results.html',
                               source_counts=source_counts.to_dict(orient='records'),
                                network_metrics=calculate_network_metric,
                               destination_counts=destination_counts.to_dict(orient='records'),
                               inactivity_gaps=inactivity_gaps.to_dict(orient='records'),
                               retransmission_packets= retransmission_packets.to_dict(orient='records'),
                               duplicate_packets=duplicate_packets.to_dict(orient='records'),
                               bandwidth1=bandwidth,
                               efficiency=efficiency,
                               tcp_latencies=tcp_latencies,
                               Outliers= Outliers.tolist(),
                               device_ips=device_ips,
                               drives=drives,
                               plot_path=plot_path,
                               plot_heatmap=plot_heatmap,
                                io_graph=io_graph,
                                bandwidth_graph=bandwidth_graph,
                                bandwidth_data=bandwidth_df.to_dict(orient='records'),
                                window_analysis_results=window_analysis_results,
                                tcp_flags_analysis=analyze_tcp_flag) 
    else:
        return render_template('index.html', error="Invalid file format, please upload a PCAP file")

 
 
if __name__ == '__main__':
    app.run(debug=True)
 
